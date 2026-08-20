package com.example.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Fastjson_1283 {
    @PostMapping("/1283")
    public String parse(@RequestBody String data) {
//        Thread.currentThread().setContextClassLoader(ParserConfig.class.getClassLoader());  // in windows, you have to uncomment this to exploit
        Object o = JSON.parse(data);
        return "parse class: " + o.getClass().getName();
    }
}