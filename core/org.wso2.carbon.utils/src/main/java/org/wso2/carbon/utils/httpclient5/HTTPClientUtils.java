/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.utils.httpclient5;

import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.util.Timeout;
import org.wso2.carbon.utils.Utils;

import javax.net.ssl.HostnameVerifier;

import static org.wso2.carbon.CarbonConstants.HOST_NAME_VERIFIER;
import static org.wso2.carbon.CarbonConstants.ALLOW_ALL;
import static org.wso2.carbon.CarbonConstants.DEFAULT_AND_LOCALHOST;

/**
 * Util methods for creating HTTP clients using Apache HTTP Client 5.
 */
public class HTTPClientUtils {

    private static final int CONNECTION_TIMEOUT;
    private static final int SOCKET_TIMEOUT;

    static {
        CONNECTION_TIMEOUT = Utils.resolveTimeout("HttpClient.Connection.TimeoutInMilliSeconds");
        SOCKET_TIMEOUT = Utils.resolveTimeout("HttpClient.Socket.TimeoutInMilliSeconds");
    }

    private HTTPClientUtils() {
        // Disable external instantiation
    }

    /**
     * Get httpclient builder with custom hostname verifier.
     *
     * @return HttpClientBuilder.
     */
    public static HttpClientBuilder createClientWithCustomHostnameVerifier() {

        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create().useSystemProperties();

        HostnameVerifier hostnameVerifier = null;
        if (DEFAULT_AND_LOCALHOST.equals(System.getProperty(HOST_NAME_VERIFIER))) {
            hostnameVerifier = LocalhostSANsTrustedHostnameVerifier.getInstance();
        } else if (ALLOW_ALL.equals(System.getProperty(HOST_NAME_VERIFIER))) {
            hostnameVerifier = NoopHostnameVerifier.INSTANCE;
        }

        if (hostnameVerifier != null) {
            httpClientBuilder.setConnectionManager(
                PoolingHttpClientConnectionManagerBuilder.create().useSystemProperties()
                    .setTlsSocketStrategy(
                        (TlsSocketStrategy) ClientTlsStrategyBuilder.create()
                            .setHostnameVerifier(hostnameVerifier)
                            .build()
                    )
                    .setDefaultConnectionConfig(
                        ConnectionConfig.custom().setConnectTimeout(Timeout.ofMilliseconds(CONNECTION_TIMEOUT))
                            .build()
                    )
                    .build()
            );
        }

        RequestConfig.Builder config = RequestConfig.custom()
                .setResponseTimeout(Timeout.ofMilliseconds(SOCKET_TIMEOUT));
        httpClientBuilder.setDefaultRequestConfig(config.build());
        return httpClientBuilder;
    }
}
