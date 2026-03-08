package com.yxj.gm;

import com.alibaba.fastjson2.JSON;

import java.util.concurrent.ConcurrentHashMap;

public class A {
    int age;
    String name;

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public static void main(String[] args) {
        A a = new A();
        a.setAge(10);
        a.setName("is A");
        String s = JSON.toJSONString(a);
        System.out.println(s);

        


        new Thread(()->{
            a.setAge(10);
        }).start();

        byte[] bytes = new byte[100];


    }
}
