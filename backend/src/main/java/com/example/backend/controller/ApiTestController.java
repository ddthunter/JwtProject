package com.example.backend.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api/test")
@RestController
public class ApiTestController {

    @RequestMapping("/hello")
    public String hello() {
        return "Hello World";
    }
}
