# FREQ DETECTOR Payment System

ระบบ login + ชำระเงิน 500 บาท → ใช้งาน 24 ชั่วโมง
ใช้ **Turso** (libSQL) เป็นฐานข้อมูล และ deploy บน **Render**

## 🚀 ขั้นตอน Deploy

### 1. สร้างฐานข้อมูล Turso

```bash
# ติดตั้ง Turso CLI
curl -sSfL https://get.tur.so/install.sh | bash

# login
turso auth login

# สร้าง database
turso db create adb

# ดู URL
turso db show adb --url
# → libsql://freq-detector-xxx.turso.io

# สร้าง token
turso db tokens create adb
# → eyJhbGciOi...