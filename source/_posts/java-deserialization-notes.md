---
title: Java 反序列化学习笔记：CC1 与 CC6 链
date: 2026-04-02 09:30:00
categories:
  - Java安全
tags:
  - Java反序列化
  - CC1
  - CC6
  - CommonsCollections
  - 利用链

---

Java 反序列化利用链的学习笔记，整理 CC1 与 CC6 两条经典链路：CC1 链围绕 InvokerTransformer、TransformMap、AbstractInputCheckedMapDecorator、AnnotationInvocationHandler 等核心类展开；CC6 链围绕 LazyMap、TiedMapEntry、HashMap 展开，并记录 payload 的构造过程与利用条件。

## 原文 PDF

<iframe src="/blog/files/java-deserialization.pdf" width="100%" height="720" style="border:1px solid #eaecef; border-radius:8px;"></iframe>

[📥 下载 PDF 原文](/blog/files/java-deserialization.pdf)
