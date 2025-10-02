package com.example.user_service.security;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {

    /**
     * Khóa bí mật để ký và xác thực token.
     * Trong ứng dụng thực tế, khóa này PHẢI được lưu trữ an toàn trong file cấu hình
     * hoặc biến môi trường, không bao giờ được viết trực tiếp trong code.
     */
    private final SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    /**
     * Thời gian hiệu lực của token (ví dụ: 1 ngày).
     * 24 giờ * 60 phút * 60 giây * 1000 mili giây.
     */
    private final long validityInMilliseconds = 24 * 60 * 60 * 1000;

    /**
     * Phương thức để tạo một JWT mới.
     * @param username Tên người dùng sẽ được lưu trong token.
     * @return một chuỗi JWT.
     */
    public String createToken(String username) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
            .setSubject(username)       // Đặt username vào trong "subject" của token
            .setIssuedAt(now)           // Thời gian phát hành token
            .setExpiration(validity)    // Thời gian hết hạn
            .signWith(secretKey)        // Ký token bằng khóa bí mật
            .compact();                 // Xây dựng và trả về chuỗi JWT
    }
}