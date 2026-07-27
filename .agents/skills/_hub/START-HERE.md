# CTF / 逆向 Skills 新手整合包

我已经把这批相关 skill 导出到当前目录下的 `skills-export/`。

## 现在的推荐入口

### 首选：`ctf-super-hub`

这是我刚给你做的 **CTF 超级总控 skill**。

它不是单一题型 skill，而是一个总入口控制器，负责：
- 自动选择最合适的 `ctf-*` skill
- 先头脑风暴，再决定怎么路由
- 支持手动指定题型，但会做 sanity check
- 支持三种输出风格：
  - `teaching`：教学模式
  - `competition`：比赛模式
  - `hints-only`：只给提示模式
- 支持跨题型 pivot
- 题做完后引导到 `ctf-writeup`

如果你只想保留一个入口，**保留它就够了**。

---

## 还有哪些入口

- `ctf-beginner-hub`：更轻量的新手入口
- `solve-challenge`：偏自动分流
- `brainstorming`：偏先理清题意
- `ctf-web / ctf-crypto / ctf-reverse / ctf-pwn / ...`：专项 skill

## 我建议的使用方式

### 方式 1：默认全都走 `ctf-super-hub`

适合绝大多数情况。

可直接复制：

```text
请使用 ctf-super-hub 帮我处理这道题。
如果你能判断题型，就自动分流到最合适的 ctf-* skill。
如果信息还不够，就先带我做最小化头脑风暴。
默认用 teaching 风格输出。

题目信息：
[粘贴题面/附件/URL/IP:PORT/源码结构/已做尝试]
```

### 方式 2：只想快速开干

```text
请使用 ctf-super-hub 的 auto + competition 模式。
先判断最像哪类题，再只告诉我接下来最该做的 1~3 步。

题目信息：
[粘贴内容]
```

### 方式 3：我只想要提示

```text
请使用 ctf-super-hub 的 auto + hints-only 模式。
不要直接把解法全展开，只告诉我下一步该查什么、为什么。

题目信息：
[粘贴内容]
```

### 方式 4：我想先梳理，再选 skill

```text
请使用 ctf-super-hub 的 brainstorm + teaching 模式。
我现在看不懂这题是什么类型。
先帮我梳理目标、线索、缺失信息，再决定自动路由还是手动路由。

题目信息：
[粘贴内容]
```

## 我这次新增/整合了什么

### 新增超级总控 skill
- `ctf-super-hub/SKILL.md`
- `ctf-super-hub/references/mode-playbook.md`
- `ctf-super-hub/references/routing-table.md`
- `ctf-super-hub/references/pivot-patterns.md`
- `ctf-super-hub/references/output-contract.md`
- `ctf-super-hub/references/prompt-library.md`
- `ctf-super-hub/references/first-five-minutes.md`
- `ctf-super-hub/references/examples.md`

### 之前已补的新手入口
- `ctf-beginner-hub/...`

### 工具与安装
- `scripts/install_ctf_tools.sh`
- `install-to-codex.sh`

## 快速安装到 Codex 技能目录

```bash
cd skills-export
./install-to-codex.sh
```

## 备注

我尝试按 skill-creator 的流程做了初始化并完成了结构化内容。

想进一步跑官方打包/校验的话，当前环境里缺少 `PyYAML`，所以官方 `quick_validate.py` 还没法直接跑；不过目录结构和文件组织已经补齐了。

## 现在新增：Strix 增强能力子集

这次不是额外再造一套主系统，而是把 Strix 作为 **原有 CTF 双模式流程的增强层** 接进去。

也就是说：
- 主入口仍然是 `ctf-super-hub`
- 新手轻入口仍然是 `ctf-beginner-hub`
- 只是当题目进入 Web / 接口 / 漏洞验证阶段时，会自动增强到合适的 `strix-*`

