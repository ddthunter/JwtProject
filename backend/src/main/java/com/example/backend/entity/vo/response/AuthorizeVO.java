package com.example.backend.entity.vo.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthorizeVO {
    String username;
    String role;
    String token;
    Date expire;
}
