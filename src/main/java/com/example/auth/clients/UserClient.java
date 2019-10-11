package com.example.auth.clients;

import com.example.auth.dto.User;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "user-service", url = "http://127.0.0.1:8082/user-service", path = "/user")
public interface UserClient {
    @RequestMapping(value = "/queryUserByName", method = RequestMethod.GET)
    ResponseEntity<User> queryUserByName(@RequestParam("userName") String userName);
}
