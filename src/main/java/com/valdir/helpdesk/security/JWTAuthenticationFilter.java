package com.valdir.helpdesk.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.valdir.helpdesk.domain.dtos.CredenciaisDTO;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private AuthenticationManager authenticationManager;
	private JWTUtil jwtUtil;

	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
		super();
		this.authenticationManager = authenticationManager;
		this.jwtUtil = jwtUtil;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		try {
			CredenciaisDTO creds = new ObjectMapper().readValue(request.getInputStream(), CredenciaisDTO.class);
			UsernamePasswordAuthenticationToken authenticationToken = 
					new UsernamePasswordAuthenticationToken(creds.getEmail(), creds.getSenha(), new ArrayList<>());
			Authentication authentication = authenticationManager.authenticate(authenticationToken);
			return authentication;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@Override
   	//@CrossOrigin(origins = "http://localhost:4200", exposedHeaders = "Authorization")
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
	
		String username = ((UserSS) auth.getPrincipal()).getUsername();
		String token = jwtUtil.generateToken(username);
		res.setHeader("Access-Control-Allow-Origin", "*");
       	res.setHeader("Access-Control-Allow-Methods", "POST, PUT, GET, OPTIONS, DELETE");
       	res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, enctype, Location");
       	res.setHeader("Access-Control-Expose-Headers","Authorization, Content-Type, enctype, Location");
       	//res.setHeader("Access-Control-Allow-Origin","*");
       	
       	

       	
       	res.setHeader("Authorization", "Bearer " + token);
	}
	
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		
		response.setStatus(401);
		response.setContentType("application/json");
		response.getWriter().append(json());
	}

	private CharSequence json() {
		long date = new Date().getTime();
		return "{"
				+ "\"timestamp\": " + date + ", " 
				+ "\"status\": 401, "
				+ "\"error\": \"Não autorizado\", "
				+ "\"message\": \"Email ou senha inválidos\", "
				+ "\"path\": \"/login\"}";
	}
//	
//	@PostMapping("/login")
//	public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
//	    // Lógica de autenticação, geração do token, etc.
//	    String token = jwtUtil.generateToken(loginRequest.getUsername()); // Gera o token
//	    
//	    HttpHeaders headers = new HttpHeaders();
//	    headers.add("Authorization", "Bearer " + token); // Adiciona o token ao cabeçalho de autorização
//	    return ResponseEntity.ok().headers(headers).body("Login successful");
//	}
	
	
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
	    // Geração do token JWT
	    String token = jwtUtil.generateToken(loginRequest.getUsername());
	    System.out.println("Token gerado: " + token); // Verificação do token gerado
	    
	    // Retornando o token no corpo da resposta
	    return ResponseEntity.ok(Collections.singletonMap("token", "Bearer " + token));
	}
	
//	@PostMapping("/login")
//	public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
//	    // Verifique se as credenciais estão chegando corretamente
//	    System.out.println("Tentativa de login com: " + loginRequest.getUsername());

//	    if (authenticate(loginRequest.getUsername(), loginRequest.getPassword())) {
//	        String token = jwtUtil.generateToken(loginRequest.getUsername());
//	        System.out.println("Token gerado: " + token); // Log do token gerado

//	        HttpHeaders headers = new HttpHeaders();
//	        headers.add("Authorization>", "Bearer " + token);
//	        return ResponseEntity.ok().headers(headers).body("Login bem-sucedido");
//	    } else {
//	        System.out.println("Credenciais inválidas"); // Log de falha de autenticação
//	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciais inválidas");
//	    }
//	}

	private boolean authenticate(String username, String password) {
		// TODO Auto-generated method stub
		return true;
	}
}
