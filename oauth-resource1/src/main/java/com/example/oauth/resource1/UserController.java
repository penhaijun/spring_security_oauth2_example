package com.example.oauth.resource1;

import com.sun.org.apache.bcel.internal.generic.RET;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author penghaijun
 * @description UserController
 * @date 2019-06-13 15:08
 **/
@RestController
public class UserController {

    @RequestMapping("/user")
    public String user() {
        return "hj";
    }
}
