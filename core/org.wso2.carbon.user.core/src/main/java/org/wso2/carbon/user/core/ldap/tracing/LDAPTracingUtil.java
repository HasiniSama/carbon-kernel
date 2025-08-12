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

import io.opentelemetry.api.trace.Span;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.ServerConfiguration;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.Control;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class that provides helper methods for OpenTelemetry-based LDAP tracing. This includes masking sensitive
 * data, formatting control/search parameters, and reading relevant configuration values.
 */
public class LDAPTracingUtil {

    private static final Log LOG = LogFactory.getLog(LDAPTracingUtil.class);

    /**
     * Retrieves the instrumentation scope name used for OpenTelemetry tracing.
     * <p>
     * This value is configured via {@code deployment.toml} and resolved using {@link ServerConfiguration} through the
     * property key {@link LDAPTracingConstants#INSTRUMENTATION_SCOPE_NAME}. It is typically used to name the tracer
     * (e.g., "wso2isldap").
     *
     * @return the name of the OpenTelemetry instrumentation scope.
     */
    public static String getInstrumentationScopeNameFromConfig() {

        String scope = ServerConfiguration.getInstance().getFirstProperty(
                LDAPTracingConstants.INSTRUMENTATION_SCOPE_NAME);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Using instrumentation scope name: " + scope + " for OpenTelemetry tracing.");
        }

        return scope;
    }

    /**
     * Determines whether OpenTelemetry tracing is enabled for LDAP operations.
     * <p>
     * This value is configured via {@code deployment.toml} and resolved using {@link ServerConfiguration} through the
     * property key {@link LDAPTracingConstants#IS_LDAP_TRACING_ENABLED}.
     *
     * @return {@code true} if OpenTelemetry tracing is enabled; {@code false} otherwise.
     */
    public static boolean isTracingEnabled() {

        boolean isEnabled = Boolean.parseBoolean(ServerConfiguration.getInstance().getFirstProperty(
                LDAPTracingConstants.IS_LDAP_TRACING_ENABLED));

        if (LOG.isDebugEnabled()) {
            LOG.debug("OpenTelemetry tracing is enabled: " + isEnabled);
        }

        return isEnabled;
    }

    /**
     * Adds LDAP control-related metadata as span attributes.
     * <p>
     * Each control's OID and criticality are included in the span for visibility.
     *
     * @param connectionControls array of LDAP {@link Control} objects passed in the request.
     * @param span               active OpenTelemetry span to annotate.
     */
    public static void addControlSpanAttributes(Control[] connectionControls, Span span) {

        if (connectionControls == null || span == null) {
            return;
        }

        for (int i = 0; i < connectionControls.length; i++) {
            Control ctrl = connectionControls[i];
            if (ctrl != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_CONTROL_PREFIX + i +
                        LDAPTracingConstants.ATTR_LDAP_CONTROL_OID_SUFFIX, ctrl.getID());
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_CONTROL_PREFIX + i +
                        LDAPTracingConstants.ATTR_LDAP_CONTROL_CRITICAL_SUFFIX, ctrl.isCritical());
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Added " + connectionControls.length + " LDAP control attributes to span.");
        }
    }

    /**
     * Masks sensitive key-value pairs in LDAP strings such as Distinguished Names (DNs) or search filters.
     * <p>
     * Example: {@code uid=john,ou=Users} becomes {@code uid=***,ou=***}.
     *
     * @param input the raw LDAP string to be masked.
     * @return a sanitized version of the input string with attribute values replaced.
     */
    public static String maskLdapString(String input) {

        if (StringUtils.isBlank(input)) {
            return input;
        }

        String masked;
        if (input.contains(LDAPTracingConstants.OPEN_BRACKET) && input.contains(LDAPTracingConstants.CLOSE_BRACKET)) {
            // Treat as LDAP filter.
            masked = maskLdapFilter(input);
        } else {
            // Treat as DN.
            masked = maskLdapDn(input);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Masked LDAP string to: " + masked);
        }

        return masked;
    }

    /**
     * Masks values in an LDAP filter string by replacing attribute values with a placeholder.
     * Skips presence filters (e.g., (uid=*)).
     *
     * @param filter the LDAP filter string.
     * @return the masked LDAP filter string.
     */
    private static String maskLdapFilter(String filter) {

        Pattern pattern = Pattern.compile(LDAPTracingConstants.LDAP_FILTER_REGEX);
        Matcher matcher = pattern.matcher(filter);
        StringBuffer result = new StringBuffer();

        while (matcher.find()) {
            String key = matcher.group(1);
            String operator = matcher.group(2);
            String value = matcher.group(3);

            if (LDAPTracingConstants.ASTERISK.equals(value.trim())) {
                matcher.appendReplacement(result, key + operator + LDAPTracingConstants.ASTERISK);
                continue;
            }

            String maskedValue;

            // Heuristic: if value contains '=', assume it's a DN.
            if (value.contains(LDAPTracingConstants.EQUALS)) {
                maskedValue = maskLdapDn(value);
            } else {
                // Normal comma-separated values.
                StringBuilder maskedValues = new StringBuilder();
                String[] values = value.split(LDAPTracingConstants.DELIMITER);
                for (int i = 0; i < values.length; i++) {
                    if (i > 0) {
                        maskedValues.append(LDAPTracingConstants.DELIMITER);
                    }
                    maskedValues.append(LDAPTracingConstants.MASKED_VALUE);
                }
                maskedValue = maskedValues.toString();
            }

            matcher.appendReplacement(result, key + operator + maskedValue);
        }

        matcher.appendTail(result);
        return result.toString();
    }

    /**
     * Masks values in an LDAP Distinguished Name (DN) by replacing each attribute value.
     *
     * @param dn the LDAP DN string.
     * @return the masked DN string.
     */
    private static String maskLdapDn(String dn) {

        // Split on comma, then mask each key=value
        String[] parts = dn.split(LDAPTracingConstants.LDAP_DN_REGEX);
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < parts.length; i++) {
            String part = parts[i].trim();

            int equalIndex = part.indexOf(LDAPTracingConstants.EQUALS_CHAR);
            if (equalIndex > 0 && equalIndex < part.length() - 1) {
                String key = part.substring(0, equalIndex).trim();
                // You can enhance this to skip masking certain keys like "objectClass"
                result.append(key).append(LDAPTracingConstants.EQUALS).append(LDAPTracingConstants.MASKED_VALUE);
            } else {
                result.append(part); // malformed component
            }

            if (i < parts.length - 1) {
                result.append(LDAPTracingConstants.DELIMITER);
            }
        }

        return result.toString();
    }

    /**
     * Generates a string representation of an LDAP {@link SearchControls} object for logging/tracing.
     * <p>
     * Captures search scope, count/time limits, and requested return attributes.
     *
     * @param controls the {@link SearchControls} object to format.
     * @return formatted string of search control properties, or {@code "null"} if input is null.
     */
    public static String formatSearchControls(SearchControls controls) {

        if (controls == null) {
            return LDAPTracingConstants.NO_SEARCH_CONTROLS;
        }

        String formatted = String.format(
                LDAPTracingConstants.FORMATTED_SEARCH_CONTROL_STRING,
                controls.getSearchScope(),
                controls.getCountLimit(),
                controls.getTimeLimit(),
                Arrays.toString(controls.getReturningAttributes()),
                controls.getDerefLinkFlag(),
                controls.getReturningObjFlag()
        );

        if (LOG.isDebugEnabled()) {
            LOG.debug("Formatted search controls: " + formatted);
        }

        return formatted;
    }

    /**
     * Masks the values of all attributes in a given {@link Attributes} object.
     *
     * @param attrs LDAP {@link Attributes} containing possibly sensitive data.
     * @return a comma-separated list of attribute names with masked values.
     */
    public static String maskAttributes(Attributes attrs) {

        StringBuilder builder = new StringBuilder();

        try {
            NamingEnumeration<? extends Attribute> allAttrs = attrs.getAll();
            while (allAttrs.hasMore()) {
                Attribute attr = allAttrs.next();
                builder.append(attr.getID()).append(LDAPTracingConstants.EQUALS).append(
                        LDAPTracingConstants.MASKED_VALUE).append(LDAPTracingConstants.DELIMITER_WITH_SPACE_SUFFIX);
            }
        } catch (NamingException namingException) {
            LOG.warn("Failed to mask attributes due to LDAP exception.");
            return LDAPTracingConstants.MASKING_ATTRIBUTE_ERROR_MESSAGE;
        }

        String maskedResult = builder.toString();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Masked attributes: " + maskedResult);
        }

        return maskedResult;
    }


    /**
     * Masks values of LDAP {@link ModificationItem}s to avoid exposing sensitive data in logs.
     *
     * @param mods array of {@link ModificationItem}s used in modify operations.
     * @return string representation of attribute names with masked values.
     */
    public static String maskModificationItems(ModificationItem[] mods) {

        StringBuilder builder = new StringBuilder();

        if (mods != null) {
            for (ModificationItem mod : mods) {
                Attribute attr = mod.getAttribute();
                if (attr != null) {
                    builder.append(attr.getID()).append(LDAPTracingConstants.EQUALS).append(
                            LDAPTracingConstants.MASKED_VALUE).append(LDAPTracingConstants.DELIMITER_WITH_SPACE_SUFFIX);
                }
            }
        }

        String maskedResult = builder.toString();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Masked modification items: " + maskedResult);
        }

        return maskedResult;
    }

    /**
     * Adds relevant attributes to the tracing span for LDAP bind or rebind operations.
     * <p>
     * This includes the distinguished name (DN), the class name of the bound object (if provided), and any associated
     * attributes. Sensitive data is masked before being added to the span.
     *
     * @param name  the distinguished name (DN) involved in the operation.
     * @param obj   the object being bound or rebound, may be {@code null}.
     * @param attrs the attributes associated with the entry, may be {@code null}.
     * @param span  the OpenTelemetry span to which the data is added.
     */
    public static void addBindRebindSpanData(String name, Object obj, Attributes attrs, Span span) {

        if (span != null) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));
            // Log the class name of the object being bound, if available.
            if (obj != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_OBJECT_CLASS, obj.getClass().getName());
            }
            if (attrs != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_ATTRS, LDAPTracingUtil.maskAttributes(attrs));
            }
        }
    }
}
