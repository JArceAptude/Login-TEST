package com.auth.security.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/***
 * Class used to send data as a response from request.
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ResponseObject {
    Object object;
    String error;
}
