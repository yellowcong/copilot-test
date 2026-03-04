package com.example.user.controller;

import com.example.user.entity.User;
import com.example.user.repository.UserRepository;
import com.example.user.security.JwtUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private ObjectMapper objectMapper;

    private String adminToken;
    private User adminUser;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        adminUser = new User();
        adminUser.setName("Admin");
        adminUser.setEmail("admin@example.com");
        adminUser.setPassword(passwordEncoder.encode("admin123"));
        adminUser.setRole("ADMIN");
        adminUser = userRepository.save(adminUser);

        adminToken = jwtUtils.generateToken(adminUser.getEmail(), adminUser.getId());
    }

    @Test
    void getAllUsers_withAdminRole_returnsUserList() throws Exception {
        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(1))))
                .andExpect(jsonPath("$[0].email", is("admin@example.com")));
    }

    @Test
    void getUserById_withAdminRole_returnsUser() throws Exception {
        mockMvc.perform(get("/api/users/" + adminUser.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email", is("admin@example.com")))
                .andExpect(jsonPath("$.name", is("Admin")));
    }

    @Test
    void createUser_withAdminRole_createsAndReturnsUser() throws Exception {
        String body = """
                {"name":"NewUser","email":"newuser@example.com","password":"pass1234","phone":"1234567890","address":"123 Main St"}
                """;

        mockMvc.perform(post("/api/users")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email", is("newuser@example.com")))
                .andExpect(jsonPath("$.name", is("NewUser")))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void updateUser_withAdminRole_updatesAndReturnsUser() throws Exception {
        String body = """
                {"name":"Updated","email":"admin@example.com","phone":"9876543210","address":"456 Other St"}
                """;

        mockMvc.perform(put("/api/users/" + adminUser.getId())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name", is("Updated")))
                .andExpect(jsonPath("$.phone", is("9876543210")));
    }

    @Test
    void deleteUser_withAdminRole_deletesUser() throws Exception {
        User toDelete = new User();
        toDelete.setName("ToDelete");
        toDelete.setEmail("delete@example.com");
        toDelete.setPassword(passwordEncoder.encode("pass1234"));
        toDelete.setRole("USER");
        toDelete = userRepository.save(toDelete);

        mockMvc.perform(delete("/api/users/" + toDelete.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/users/" + toDelete.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound());
    }

    @Test
    void getAllUsers_withoutToken_returnsForbiddenOrUnauthorized() throws Exception {
        mockMvc.perform(get("/api/users"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    void createUser_withNonAdminRole_returnsForbidden() throws Exception {
        User regularUser = new User();
        regularUser.setName("Regular");
        regularUser.setEmail("regular@example.com");
        regularUser.setPassword(passwordEncoder.encode("pass1234"));
        regularUser.setRole("USER");
        regularUser = userRepository.save(regularUser);
        String userToken = jwtUtils.generateToken(regularUser.getEmail(), regularUser.getId());

        String body = """
                {"name":"Another","email":"another@example.com","password":"pass1234"}
                """;

        mockMvc.perform(post("/api/users")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isForbidden());
    }
}
