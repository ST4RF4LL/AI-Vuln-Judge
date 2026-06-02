# 静态分析 Markdown 报告

## 发现 1：python-command-injection

- 规则：python-command-injection
- 严重性：error
- 消息：用户输入可到达命令执行点
- 位置：app.py:5:5

### 代码流

- app.py:4:11
- app.py:5:5
