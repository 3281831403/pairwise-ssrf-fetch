# pairwise-ssrf-fetch

## 题面

接入第三方链接预览服务后，抓取器开始被当成内网跳板：只按字符串判断内网，十进制的 2130706433、IPv4-mapped IPv6 和八进制写法都能绕过；解析一次就把域名交给客户端再解析一次，DNS 重绑定后第二次直接指向内网；重定向由客户端自动跟随，第二跳不再校验；userinfo、端口与 scheme 都不看，http://user@127.0.0.1:6379/ 直接可用；响应大小与超时没有上限，慢速灌流就能拖住工作线程。linkpreview/fetch.py 是核心，tests/test_fetch.py 15个红。要修的是：用 ipaddress 归一所有 IP 变形；解析结果全部校验后再请求；手动跟随重定向并逐跳复验；userinfo、端口、scheme 三项白名单；按字节数中断并设总超时。

## 运行方式

在仓库根目录执行：

```powershell
python -m pytest tests -q
```

初始状态是可直接运行的失败环境：`linkpreview/fetch.py` 中 5 个函数都是抛出 `NotImplementedError` 的桩，因此测试结果应恰好为 `15 failed`，不能出现 collection error，也不能出现 import 或 syntax error。

测试不联网、不随机。DNS 解析器 `resolver(host)` 与网络打开器 `opener(url, timeout)` 都由调用方注入，测试只使用假实现；`tests/` 下的测试不可修改。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 目录

```text
pairwise-ssrf-fetch/
  README.md
  conftest.py
  .gitignore
  linkpreview/__init__.py
  linkpreview/fetch.py
  tests/test_fetch.py
```
