package com.example.controller;

import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.xml.ws.Holder;

@RestController
public class ParseController {

    @PostMapping("/test")
    public String test(@RequestParam String remoteClass){
//        ClassLoader loader = ParserConfig.class.getClassLoader();
        ClassLoader loader =  Thread.currentThread().getContextClassLoader();
        String loader_name = loader.getClass().getName();
        Class c;
        try{
            c = loader.loadClass(remoteClass);
        } catch (ClassNotFoundException e) {
            return "loader : " + loader_name + " failed to load "  + remoteClass;
        }
        return "loader : " + loader_name + " successfully load class : " + remoteClass + "\nresult is " + c.getName();
    }

    @PostMapping("/parse/1283")
    public String parse_1283(@RequestBody String data) {
//        Thread.currentThread().setContextClassLoader(ParserConfig.class.getClassLoader());  // in windows, you have to uncomment this to exploit
        Object o = com.alibaba.fastjson.JSON.parse(data);
        return "parse class: " + o.getClass().getName();
    }

    @PostMapping("/parse/2062")
    public String parse_2062(@RequestParam Boolean isParseObject, @RequestBody String data) {
        //        Thread.currentThread().setContextClassLoader(ParserConfig.class.getClassLoader());  // in windows, you have to uncomment this to exploit?? DynamicClassLoader ???????
        Object o;
        if(isParseObject){
            o = com.alibaba.fastjson2.JSON.parseObject(data, Object.class);
        }else{
            o = com.alibaba.fastjson2.JSON.parse(data);
        }
        return o.toString();
    }
}
