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

package org.wso2.carbon.user.core.ldap.tracing;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.MDC;

import javax.naming.Context;
import java.net.URI;
import java.util.Hashtable;

/**
 * Utility class responsible for creating and managing OpenTelemetry spans for LDAP operations. This class wraps the
 * creation and enrichment of a span for a given LDAP operation (e.g., bind, search, newInstance) and provides methods
 * to mark the span as successful or errored.
 */
public class LDAPTracingSpan {

    private static final Log LOG = LogFactory.getLog(LDAPTracingSpan.class);

    // OpenTelemetry tracer instance for creating spans
    private static final Tracer TRACER = GlobalOpenTelemetry.getTracer(
            LDAPTracingUtil.getInstrumentationScopeNameFromConfig()
    );

    private final Span span;

    /**
     * Private constructor to create and start a new LDAP tracing span.
     *
     * @param operationName The LDAP operation being traced (e.g., "bind", "search").
     * @param environment   The environment Hashtable containing the LDAP provider URL.
     */
    private LDAPTracingSpan(String operationName, Hashtable<?, ?> environment) {

        this.span = TRACER.spanBuilder(LDAPTracingConstants.SPAN_NAME_LDAP_PREFIX + operationName)
                .setSpanKind(SpanKind.CLIENT)
                .startSpan();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Started LDAP tracing span for operation: " + operationName);
        }

        setLdapPeerAttributes(environment, span);
        setCorrelationId(span);
    }

    /**
     * Factory method to start a new LDAP tracing span.
     *
     * @param operationName The name of the LDAP operation.
     * @param environment   The LDAP environment configuration.
     * @return An instance of LDAPTracingSpan.
     */
    public static LDAPTracingSpan start(String operationName, Hashtable<?, ?> environment) {

        return new LDAPTracingSpan(operationName, environment);
    }

    /**
     * Returns the underlying OpenTelemetry span instance.
     */
    public Span span() {

        return span;
    }

    /**
     * Marks the span as successful and ends it.
     */
    public void success() {

        span.setAttribute(LDAPTracingConstants.ATTR_LDAP_SUCCESS, true);
        span.end();

        if (LOG.isDebugEnabled()) {
            LOG.debug("LDAP span marked as successful and ended.");
        }
    }

    /**
     * Records an error in the span and ends it.
     *
     * @param exception The exception encountered during the LDAP operation.
     */
    public void error(Exception exception) {

        span.recordException(exception);
        span.setStatus(StatusCode.ERROR, exception.getMessage());
        span.end();

        LOG.warn("LDAP span ended with error: " + exception.getMessage());
    }

    /**
     * Sets the correlation ID attribute in the span from the MDC.
     *
     * @param span The span to update.
     */
    private static void setCorrelationId(Span span) {

        String correlationId = MDC.get(LDAPTracingConstants.CORRELATION_ID_MDC);
        if (correlationId != null) {
            span.setAttribute(LDAPTracingConstants.ATTR_CORRELATION_ID, correlationId);
        }
    }

    /**
     * Extracts host and port from the LDAP provider URL and sets them as attributes in the span.
     * Falls back to "unknown" if the URL is malformed or unavailable.
     *
     * @param environment The LDAP environment (e.g., containing Context.PROVIDER_URL).
     * @param span        The OpenTelemetry span to annotate.
     */
    private static void setLdapPeerAttributes(Hashtable<?, ?> environment, Span span) {

        try {
            Object urlObj = (environment != null) ? environment.get(Context.PROVIDER_URL) : null;
            String providerUrl = (urlObj != null) ? urlObj.toString().trim() : null;

            if (StringUtils.isBlank(providerUrl)) {
                LOG.warn("LDAP provider URL is empty or missing. Using fallback values.");
                span.setAttribute(LDAPTracingConstants.ATTR_PEER_SERVICE, LDAPTracingConstants.PEER_SERVICE_VALUE);
                return;
            }

            String[] urls = providerUrl.split(LDAPTracingConstants.LDAP_PROVIDER_URL_REGEX);
            String firstUrl = urls[0];

            // Ensure the URL has a valid scheme, default to ldap:// if missing.
            if (!firstUrl.matches(LDAPTracingConstants.LDAP_SCHEME_URL_REGEX)) {
                firstUrl = LDAPTracingConstants.LDAP_DEFAULT_SCHEME_PREFIX + firstUrl;
            }

            URI ldapUri = new URI(firstUrl);
            String host = ldapUri.getHost();
            int port = ldapUri.getPort();

            if (StringUtils.isBlank(host)) {
                LOG.warn("Host is missing in the LDAP provider URL. Using fallback.");
            }

            // Default port if not specified.
            if (port == -1) {
                port = LDAPTracingConstants.LDAPS_SCHEME.equalsIgnoreCase(ldapUri.getScheme())
                        ? LDAPTracingConstants.LDAPS_DEFAULT_PORT
                        : LDAPTracingConstants.LDAP_DEFAULT_PORT;
            }

            span.setAttribute(LDAPTracingConstants.ATTR_PEER_SERVICE, LDAPTracingConstants.PEER_SERVICE_VALUE);
            if (StringUtils.isNotBlank(providerUrl)) {
                span.setAttribute(LDAPTracingConstants.ATTR_NET_PEER_HOSTNAME, host);
            }
            span.setAttribute(LDAPTracingConstants.ATTR_NET_PEER_PORT, port);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Configured LDAP peer attributes - host: " + host + ", port: " + port);
            }

        } catch (Exception exception) {
            LOG.warn("Failed to parse LDAP provider URL. Using fallback values." + exception.getMessage());
            span.setAttribute(LDAPTracingConstants.ATTR_PEER_SERVICE, LDAPTracingConstants.PEER_SERVICE_VALUE);
        }
    }
}
