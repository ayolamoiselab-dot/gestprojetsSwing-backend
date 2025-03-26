package com.example.demo;


import com.example.demo.config.FirebaseInitializer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class GestprojetsApplication {

	public static void main(String[] args) {
                FirebaseInitializer.initialize();
		SpringApplication.run(GestprojetsApplication.class, args);
	}

}
