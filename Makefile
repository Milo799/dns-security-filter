# DNS 安全过滤中间件 - Harness 工程 Makefile
# 验收基准：make dev 一键启动 → make verify 验证链路 → make test 全绿 → make docker-up 容器化部署

PYTHON ?= python3
GO     ?= go

.PHONY: dev proxy platform verify test init init-db clean docker-up docker-down docker-logs loadtest

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

## 运行全部测试（352 项；conftest 已设 DNSF_TESTING=1 隔离公网源）
test:
	cd platform && $(PYTHON) -m pytest ../tests -v

## 安装平台依赖
init:
	cd platform && pip install -r requirements.txt

## 初始化数据库（建表 + 默认管理员 + 默认配置 + 内置情报源）
init-db:
	cd platform && $(PYTHON) -m seed

## Docker 一键构建启动（平台 DNS:53 + Web:8080，代理:53）
docker-up:
	docker compose -f deploy/docker/docker-compose.yml up -d --build

## 停止并移除容器
docker-down:
	docker compose -f deploy/docker/docker-compose.yml down

## 查看容器日志
docker-logs:
	docker compose -f deploy/docker/docker-compose.yml logs -f

## DNS 压测（QPS/延迟分位；Windows 须 SelectorEventLoop，脚本已内置）
loadtest:
	cd platform && $(PYTHON) ../tools/loadtest.py $(TARGET) --qps $(QPS)
