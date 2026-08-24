# DNS 安全过滤中间件 - Harness 工程 Makefile
# 验收基准：make dev 一键启动 → make verify 验证链路 → make test 全绿

PYTHON ?= python3
GO     ?= go

.PHONY: dev proxy platform web verify test init clean

## 一键启动本地开发环境（代理 + 平台），前台运行
dev:
	@bash scripts/dev.sh

## 仅构建并运行代理（需 Go 1.21+）
proxy:
	cd proxy && $(GO) build -o ../bin/dns-proxy . && cd ..
	@echo "代理已构建：bin/dns-proxy"

## 仅启动平台（DNS + Web，需 Python 3.10+）
platform:
	cd platform && $(PYTHON) -m uvicorn app.main:app --host 0.0.0.0 --port 8080 & \
	$(PYTHON) dns_server.py

## 端到端验证：dig 通过代理查询，确认链路通
verify:
	@bash scripts/verify.sh

## 运行单元测试锚点
test:
	cd platform && $(PYTHON) -m pytest ../tests -v

## 安装平台依赖
init:
	cd platform && pip install -r requirements.txt

## 初始化数据库（建表 + 默认管理员 + 默认配置）
init-db:
	cd platform && $(PYTHON) -m seed
