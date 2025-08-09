# Cloudflare 优选 IP 聚合（每 6 小时）

自动从以下 4 个源抓取优选 IP，合并去重生成 `ip.txt`：
- https://cf.vvhan.com
- https://cf.090227.xyz
- https://ip.164746.xyz
- https://stock.hostmonit.com/CloudFlareYes

## 用法
1. 将本仓库推送到 GitHub，并确保默认分支为 `main`。
2. GitHub Actions 会在每 6 小时自动运行，更新 `ip.txt`。
3. 也可在 Actions 页面手动触发（workflow_dispatch）。

## 本地运行
```bash
pip install -r requirements.txt
python collect_ips.py
# 生成 ip.txt
