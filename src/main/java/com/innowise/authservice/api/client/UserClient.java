package com.innowise.authservice.api.client;

import com.innowise.authservice.core.config.FeignClientConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(
    name = "userservice",
    url = "${user.service.url}",
    path = "/api/users",
    configuration = FeignClientConfig.class
)
public interface UserClient {

    @GetMapping("/email")
    GetUserDto getUserByEmail(@RequestParam("email") String email);
}
