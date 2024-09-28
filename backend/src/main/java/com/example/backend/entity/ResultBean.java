package com.example.backend.entity;

import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;

public record ResultBean<T>(int code, String msg, T data) {
    public static <T> ResultBean<T> success(T data) {
        return new ResultBean<>(200, "请求成功", data);
    }

    public static <T> ResultBean<T> success() {
        return success(null);
    }

    public static <T> ResultBean<T> failure(int code, String msg) {
        return new ResultBean<>(code, msg, null);
    }

    public String asJsonString() {
        return JSONObject.toJSONString(this, JSONWriter.Feature.WriteNulls);
    }
}
