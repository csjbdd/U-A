package com.example.erp.controller;

import com.example.erp.model.MemberLoginRequestDto;
import com.example.erp.model.TokenInfo;
import com.example.erp.service.impl.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
@CrossOrigin
public class MemberController {
    private final MemberService memberService;

    @PostMapping("/login")
    public TokenInfo login(@RequestBody MemberLoginRequestDto memberLoginRequestDto) {
        String memberId = memberLoginRequestDto.getMemberId();
        String password = memberLoginRequestDto.getPassword();
        TokenInfo tokenInfo = memberService.login(memberId, password);
        return tokenInfo;
    }
    @PostMapping("/test")
    public String test() {
        return "success";
    }
}
