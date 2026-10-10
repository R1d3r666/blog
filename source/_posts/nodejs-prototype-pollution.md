---
title: Node.js 原型链污染（Prototype Pollution）
date: 2026-04-02 10:00:00
categories:
  - Node.js安全
tags:
  - Node.js
  - 原型链污染
  - JavaScript安全

---

## 概述

原型链污染（Prototype Pollution）是一种针对 JavaScript 运行时的安全漏洞，攻击者通过操纵对象的原型（`__proto__` 或 `prototype`）来修改应用程序的行为，可能导致拒绝服务、信息泄露、远程代码执行等严重后果。

在 Node.js 环境中，由于 JavaScript 是服务端语言，原型链污染的影响更为严重，可能直接导致服务器被入侵。

## 基本原理

### JavaScript 原型链

JavaScript 使用原型继承机制。每个对象都有一个内部属性 `[[Prototype]]`（可通过 `__proto__` 或 `Object.getPrototypeOf()` 访问），指向其原型对象。当访问对象的属性时，如果对象自身没有该属性，JavaScript 会沿着原型链向上查找。

```javascript
const obj = {};
obj.__proto__.foo = 'bar';
console.log(obj.foo); // 输出 'bar'，因为 obj 本身没有 foo，但原型上有
```

### 污染点

原型链污染通常发生在以下场景：
1. **对象合并**：使用 `Object.assign()`、`lodash.merge()`、`jQuery.extend()` 等函数时，如果未正确处理原型属性。
2. **JSON 解析**：使用 `JSON.parse()` 解析用户输入的 JSON 字符串时，如果字符串包含 `__proto__` 属性。
3. **路径赋值**：通过 `lodash.set()` 或类似函数动态设置属性路径时，路径中包含 `__proto__`。

## 攻击示例

### 示例1：通过对象合并污染

```javascript
const merge = (target, source) => {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
};

const malicious = JSON.parse('{"__proto__":{"polluted":"yes"}}');
const obj = {};
merge(obj, malicious);
console.log({}.polluted); // 输出 'yes'，原型已被污染
```

### 示例2：通过 lodash.merge 污染

```javascript
const _ = require('lodash');
const malicious = JSON.parse('{"__proto__":{"admin":true}}');
const obj = {};
_.merge(obj, malicious);
console.log({}.admin); // 输出 true
```

### 示例3：通过路径赋值污染

```javascript
const _ = require('lodash');
_.set({}, '__proto__.polluted', 'yes');
console.log({}.polluted); // 输出 'yes'
```

## 危害

1. **拒绝服务（DoS）**：污染 `Object.prototype` 的常用方法（如 `toString`、`valueOf`）可能导致应用程序崩溃。
2. **权限提升**：如果应用程序检查 `user.isAdmin` 属性，攻击者可通过污染 `Object.prototype.isAdmin` 使所有用户成为管理员。
3. **远程代码执行（RCE）**：结合其他漏洞（如模板注入），原型链污染可能导致 RCE。
4. **信息泄露**：污染 `console.log` 或日志函数，窃取敏感数据。

## 实际案例

### CVE-2019-10744：lodash 原型链污染

lodash 版本 < 4.17.12 中的 `defaultsDeep`、`merge`、`set` 等函数未正确过滤 `__proto__`，导致原型链污染。攻击者可利用此漏洞修改应用程序行为。

### CVE-2020-8203：node-ip 原型链污染

node-ip 库的 `set` 函数存在原型链污染，影响 Express 等框架。

## 检测方法

### 手动检测

1. 查找代码中使用 `merge`、`extend`、`assign`、`set` 等函数的地方。
2. 检查是否对用户输入的 JSON 进行了解析并直接用于对象操作。
3. 使用以下 Payload 测试：
   ```json
   {"__proto__":{"polluted":"test"}}
   ```
   ```json
   {"constructor":{"prototype":{"polluted":"test"}}}
   ```

### 自动化工具

- **npm audit**：检查依赖中已知的原型链污染漏洞。
- **CodeQL**：使用静态分析检测原型链污染模式。
- **ESLint 插件**：如 `eslint-plugin-security` 可检测不安全的合并操作。

## 防护措施

### 1. 使用安全的合并函数

避免使用不安全的合并函数，改用以下方式：

```javascript
// 使用 Object.assign（浅拷贝，但不会遍历原型链）
const safeAssign = (target, ...sources) => Object.assign(target, ...sources);

// 使用 lodash 4.17.12 及以上版本（已修复）
const _ = require('lodash');
```

### 2. 过滤原型属性

在合并前检查键名是否为 `__proto__`、`constructor`、`prototype`：

```javascript
const safeMerge = (target, source) => {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            safeMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
};
```

### 3. 使用 Object.create(null)

创建无原型的对象，避免原型链污染：

```javascript
const obj = Object.create(null); // obj.__proto__ 为 undefined
```

### 4. 冻结原型

在应用程序启动时冻结 `Object.prototype`：

```javascript
Object.freeze(Object.prototype);
Object.freeze(Object);
Object.freeze(Array.prototype);
```

### 5. 输入验证

对用户输入的 JSON 进行严格验证，拒绝包含 `__proto__`、`constructor`、`prototype` 的键名，和可执行参数`require`、`input`、`loader`等。

### 6. 更新依赖

定期更新 lodash、jQuery 等库到最新版本，避免已知漏洞。

## 在 Node.js 环境中的特殊考虑

Node.js 内置模块（如 `fs`、`http`）也可能受到原型链污染的影响，因为它们是 JavaScript 对象。例如，污染 `fs.readFile` 可能导致文件读取被劫持。

### 示例：污染 fs 模块

```javascript
const fs = require('fs');
Object.prototype.readFile = function(path, callback) {
    console.log('Hacked!');
    callback(null, 'malicious content');
};
// 之后所有 fs.readFile 调用都会被劫持
```

## 绕过姿势

防护措施虽然能有效防御常见的原型链污染攻击，但攻击者仍可能利用一些技巧绕过防护。以下是一些已知的绕过姿势：

### 1. 使用 `constructor.prototype` 替代 `__proto__`

许多防护代码只检查 `__proto__` 键名，但攻击者可以使用 `constructor.prototype` 达到同样的效果：

```json
{"constructor": {"prototype": {"polluted": "yes"}}}
```

当对象合并时，`constructor` 属性指向对象的构造函数，其 `prototype` 属性即为原型对象。

### 2. 利用数组索引污染原型

在某些库中，如果使用路径赋值（如 `lodash.set`），可以通过数组索引访问原型：

```javascript
// 假设存在路径赋值函数
set(obj, 'a[0].constructor.prototype.polluted', 'yes');
```

### 3. 污染 `Object.prototype` 的 getter/setter

通过定义 getter 或 setter，可以在属性被访问时执行代码：

```javascript
Object.defineProperty(Object.prototype, 'polluted', {
    get: function() {
        console.log('Getter triggered');
        return 'hacked';
    },
    enumerable: true
});
```

### 4. 利用 JSON.parse 的 reviver 参数

`JSON.parse` 的第二个参数 `reviver` 函数在解析每个键值对时被调用，攻击者可以在此函数中污染原型：

```javascript
const maliciousJSON = '{"__proto__":{"polluted":"yes"}}';
JSON.parse(maliciousJSON, (key, value) => {
    if (key === '__proto__') {
        Object.assign(Object.prototype, value);
    }
    return value;
});
```

### 5. 污染通过 `eval` 或 `Function` 创建的对象的原型

如果应用程序使用 `eval` 或 `Function` 构造函数动态创建对象，攻击者可能污染这些对象的原型。

### 6. 利用 Node.js 内置模块的原型

Node.js 内置模块（如 `Buffer`、`Stream`）的原型也可能被污染，导致意想不到的行为。

```javascript
Buffer.prototype.read = function() {
    console.log('Buffer read hijacked');
};
```

### 7. 绕过键名过滤

如果防护代码使用黑名单过滤 `__proto__`、`constructor`、`prototype`，攻击者可能使用 Unicode 编码、大小写变换或空格绕过：

```json
{"__proto__\u200b": {"polluted": "yes"}}
{"__PROTO__": {"polluted": "yes"}}
{"__proto__ ": {"polluted": "yes"}}
```

### 8. 短参数名

如果过滤了`require`、`input`、`loader`等。
可以使用`-r`来取得同样效果。
