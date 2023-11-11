package com.example.erp.model;

import lombok.Data;

@Data
public class MemberLoginRequestDto {
    private String memberId;
    private String password;
}
