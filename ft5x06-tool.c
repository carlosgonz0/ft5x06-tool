/*
 * FT8622 FORENSIC TOOL FOR LIBREM 5
 * Copyright (C) 2025
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * ---------------------------------------------------------
 * DESCRIPTION:
 * Forensic tool for FocalTech Touch Controllers.
 * Used for Register Dumping (-t) and Blind Fuzzing (-f).
 *
 * COMPILE:
 * gcc ft_forensic.c -o ft_forensic
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>

/* Registers */
#define FT_REG_RESET_FW        0x07
#define FT_PARAM_READ_REG      0x85   /* Start of Config Data */
#define FT_READ_ID_REG         0x90
#define FT_RST_CMD_REG1        0xfc

/* Config */
#define FT_UPGRADE_AA          0xAA
#define FT_UPGRADE_55          0x55
#define FT_UPGRADE_LOOP        30

/* Logging Macros */
#define LOG(fmt, arg...) fprintf(stdout, "[INFO]: " fmt "\n" , ## arg)
#define ERR(fmt, arg...) fprintf(stderr, "[ERROR]: " fmt "\n" , ## arg)

static inline void msleep(int delay) { usleep(delay*1000); }

struct ft5x06_ts {
    int fd;
    uint8_t bus;
    uint8_t addr;
};

/* --- I2C HELPERS --- */
static int ft_i2c_transfer(struct ft5x06_ts *ts, uint8_t *tx, int tx_len, uint8_t *rx, int rx_len) {
    struct i2c_rdwr_ioctl_data data;
    struct i2c_msg msgs[2];
    int nmsgs = 0;

    if (tx_len > 0) {
        msgs[nmsgs].addr = ts->addr;
        msgs[nmsgs].flags = 0;
        msgs[nmsgs].len = tx_len;
        msgs[nmsgs].buf = tx;
        nmsgs++;
    }
    if (rx_len > 0) {
        msgs[nmsgs].addr = ts->addr;
        msgs[nmsgs].flags = I2C_M_RD;
        msgs[nmsgs].len = rx_len;
        msgs[nmsgs].buf = rx;
        nmsgs++;
    }
    data.msgs = msgs;
    data.nmsgs = nmsgs;
    return ioctl(ts->fd, I2C_RDWR, &data);
}

static void ft_reset_chip(struct ft5x06_ts *ts) {
    uint8_t buf[] = { FT_REG_RESET_FW };
    ft_i2c_transfer(ts, buf, 1, NULL, 0);
    msleep(100);
}

/* --- BOOTLOADER ENTRY SEQUENCE --- */
/* This sequence wakes up the chip and prepares it for commands */
static int ft_enter_upgrade(struct ft5x06_ts *ts) {
    int i;
    uint8_t cmd_reset_aa[] = { FT_RST_CMD_REG1, FT_UPGRADE_AA };
    uint8_t cmd_reset_55[] = { FT_RST_CMD_REG1, FT_UPGRADE_55 };
    uint8_t cmd_enter[]    = { FT_UPGRADE_55, FT_UPGRADE_AA };
    uint8_t cmd_check_id[] = { FT_READ_ID_REG };
    uint8_t id_val[2];

    for (i = 0; i < FT_UPGRADE_LOOP; i++) {
        ft_i2c_transfer(ts, cmd_reset_aa, 2, NULL, 0);
        msleep(10);
        ft_i2c_transfer(ts, cmd_reset_55, 2, NULL, 0);
        msleep(10);
        ft_i2c_transfer(ts, cmd_enter, 2, NULL, 0);
        
        msleep(20);
        if (ft_i2c_transfer(ts, cmd_check_id, 1, id_val, 2) >= 0) {
            // If we get a valid ID (not 00 or FF), we are in.
            if (id_val[0] != 0x00 && id_val[0] != 0xFF) return 0;
        }
    }
    return -1;
}

/* --- OPTION -t : REGISTER DUMP --- */
static void run_test_mode(struct ft5x06_ts *ts) {
    uint8_t cmd[1] = { 0x80 }; // Start reading from 0x80 (Config Start)
    uint8_t data[32];
    int i;

    LOG("Starting Register Dump (-t)...");
    
    if (ft_enter_upgrade(ts) < 0) {
        ERR("Failed to enter bootloader. Is driver unbound?");
        return;
    }

    LOG("Reading CONFIG register (0x80) - Hardware DNA...");
    msleep(20);
    
    if (ft_i2c_transfer(ts, cmd, 1, data, 32) < 0) {
        ERR("I2C Read Failed.");
    } else {
        printf("\n--- CONFIG DUMP (0x80 - 0xA0) ---\n");
        for (i = 0; i < 32; i++) {
            printf("%02x ", data[i]);
            if ((i+1)%16 == 0) printf("\n");
        }
        printf("---------------------------------\n");
        
        // Check for the known pattern
        if (data[0] == 0x08 && data[2] == 0x50) 
            printf("RESULT: [SUCCESS] Standard FT8622 config found!\n");
        else 
            printf("RESULT: [WARNING] Unknown config or protected.\n");
    }

    LOG("Resetting chip...");
    ft_reset_chip(ts);
}

/* --- OPTION -f : FUZZER MODE --- */
static void run_fuzzer_mode(struct ft5x06_ts *ts) {
    int cmd;
    uint8_t data[8];
    int i, interesting;

    LOG("Starting Blind Fuzzer (-f)...");
    printf("Scanning all commands 0x00 - 0xFF looking for hidden data.\n");
    printf("Ignoring responses: 0xEF (Protected), 0xFF (Bus Err), 0x00 (Empty)\n\n");

    if (ft_enter_upgrade(ts) < 0) {
        ERR("Failed to enter bootloader.");
        return;
    }

    for (cmd = 0; cmd <= 0xFF; cmd++) {
        uint8_t tx[] = { (uint8_t)cmd }; 
        
        // Try reading 8 bytes
        if (ft_i2c_transfer(ts, tx, 1, data, 8) < 0) continue;

        // Analyze: Is it interesting?
        interesting = 0;
        for(i=0; i<8; i++) {
            if (data[i] != 0xEF && data[i] != 0xFF && data[i] != 0x00) interesting = 1;
        }

        if (interesting) {
            printf("[CMD 0x%02X] -> FOUND: ", cmd);
            for(i=0; i<8; i++) printf("%02x ", data[i]);
            printf("\n");
        }
        usleep(5000); // Be nice to the bus
    }
    
    printf("\nScan Complete.\n");
    ft_reset_chip(ts);
}

/* --- MAIN --- */
int main(int argc, const char *argv[])
{
    struct ft5x06_ts ts = {-1, 2, 0x38}; // Default Bus 2, Addr 0x38
    char dev[20];
    int mode = 0; // 1=test, 2=fuzz
    int arg_count = 1;

    /* Parse Args (Classic Style) */
    while (arg_count < argc) {
        if (!strcmp(argv[arg_count], "-b")) ts.bus = atoi(argv[++arg_count]);
        else if (!strcmp(argv[arg_count], "-a")) ts.addr = strtol(argv[++arg_count], NULL, 16);
        else if (!strcmp(argv[arg_count], "-t")) mode = 1;
        else if (!strcmp(argv[arg_count], "-f")) mode = 2;
        arg_count++;
    }

    /* Open I2C */
    sprintf(dev, "/dev/i2c-%d", ts.bus);
    ts.fd = open(dev, O_RDWR);
    if (ts.fd < 0) { ERR("Cannot open %s", dev); return 1; }
    ioctl(ts.fd, I2C_SLAVE_FORCE, ts.addr);

    if (mode == 1) run_test_mode(&ts);
    else if (mode == 2) run_fuzzer_mode(&ts);
    else printf("Usage: %s -b 2 -a 0x38 [-t | -f]\n  -t : Register Dump (Fingerprint)\n  -f : Fuzz Commands (Research)\n", argv[0]);

    close(ts.fd);
    return 0;
}
