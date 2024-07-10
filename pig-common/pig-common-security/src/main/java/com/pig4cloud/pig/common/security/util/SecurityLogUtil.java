package com.pig4cloud.pig.common.security.util;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;
import org.slf4j.Logger;

import javax.annotation.Nullable;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@SuppressWarnings("ALL")
public class SecurityLogUtil {
	public static void logValue(Logger log, String classTag, String methodTag, String key, Object value) {
		ObjectMapper objectMapper = SecurityLogUtil.getObjectMapper();
		try {
			log.info("|kr.mao|[{}] {} {}={}", classTag, methodTag, key, objectMapper.writeValueAsString(value));
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
	}

	public static ObjectMapper getObjectMapper() {
		ObjectMapper objectMapper = new ObjectMapper();
		// jdk8日期格式支持
		DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
		DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
		Module timeModule = new JavaTimeModule()
				.addDeserializer(LocalDate.class, new LocalDateDeserializer(dateFormatter))
				.addDeserializer(LocalDateTime.class, new LocalDateTimeDeserializer(timeFormatter))
				.addSerializer(LocalDate.class, new LocalDateSerializer(dateFormatter))
				.addSerializer(LocalDateTime.class, new LocalDateTimeSerializer(timeFormatter));
		objectMapper.registerModule(timeModule);
		objectMapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
		objectMapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
		return objectMapper;
	}

	public static @Nullable String getValueString(Object value) {
		ObjectMapper objectMapper = SecurityLogUtil.getObjectMapper();
		try {
			return objectMapper.writeValueAsString(value);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		return null;
	}
}
