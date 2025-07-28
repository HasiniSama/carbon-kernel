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

/**
 * Constants used for LDAP OpenTelemetry tracing.
 */
public class LDAPTracingConstants {

    // Configurations required for Tracing.
    public static final String IS_LDAP_TRACING_ENABLED = "Tracing.OpenTelemetry.LDAP.Enable";
    public static final String INSTRUMENTATION_SCOPE_NAME = "Tracing.OpenTelemetry.LDAP.ScopeName";

    // Span name prefix for all LDAP operations.
    public static final String SPAN_NAME_LDAP_PREFIX = "ldap.";

    // Indicates if the LDAP context is initialized for a user credential-based flow.
    public static final String ENV_CREDENTIAL_FLOW = "ldap.user.credential.flow";

    // Span attributes for tracing context metadata.
    public static final String ATTR_CORRELATION_ID = "correlation_id";
    public static final String ATTR_LDAP_ATTRS = "ldap.attributes";
    public static final String ATTR_LDAP_AUTH_RESULT = "ldap.auth.result";
    public static final String ATTR_LDAP_AUTH_RESULT_INVALID_CREDENTIALS = "invalid_credentials";
    public static final String ATTR_LDAP_CONTEXT_ORIGIN = "ldap.context.origin";
    public static final String ATTR_LDAP_CONTEXT_ORIGIN_SYSTEM_VALUE = "system_initialization";
    public static final String ATTR_LDAP_CONTEXT_ORIGIN_USER_VALUE = "user_credentials_initialization";
    public static final String ATTR_LDAP_CONTROL_PREFIX = "ldap.control[";
    public static final String ATTR_LDAP_CONTROL_OID_SUFFIX = "].oid";
    public static final String ATTR_LDAP_CONTROL_CRITICAL_SUFFIX = "].critical";
    public static final String ATTR_LDAP_DN = "ldap.dn";
    public static final String ATTR_LDAP_DN_NEW = "ldap.dn.new";
    public static final String ATTR_LDAP_DN_OLD = "ldap.dn.old";
    public static final String ATTR_LDAP_EXTENDED_OPERATION_ID = "ldap.extended.operation.id";
    public static final String ATTR_LDAP_FILTER = "ldap.filter";
    public static final String ATTR_LDAP_FILTER_ARGS_LENGTH = "ldap.filter.args.length";
    public static final String ATTR_LDAP_FILTER_EXPRESSION = "ldap.filter.expression";
    public static final String ATTR_LDAP_MATCHING_ATTRS = "ldap.matching.attributes";
    public static final String ATTR_LDAP_MODIFICATION_ITEMS = "ldap.modification.items";
    public static final String ATTR_LDAP_MODIFICATION_ITEM_COUNT = "ldap.modification.item.count";
    public static final String ATTR_LDAP_MODIFY_OPERATION = "ldap.modify.operation";
    public static final String ATTR_LDAP_OBJECT_CLASS = "ldap.object.class";
    public static final String ATTR_LDAP_RETURN_ATTRS = "ldap.return.attributes";
    public static final String ATTR_LDAP_SEARCH_CONTROLS = "ldap.search.controls";
    public static final String ATTR_LDAP_SUCCESS = "ldap.success";
    public static final String ATTR_PEER_SERVICE = "peer.service";
    public static final String ATTR_NET_PEER_HOSTNAME = "peer.hostname";
    public static final String ATTR_NET_PEER_PORT = "peer.port";
    public static final String ATTR_LDAP_USER_DN = "ldap.user_dn";

    // MDC key used to extract correlation ID.
    public static final String CORRELATION_ID_MDC = "Correlation-ID";

    // Misc constants.
    public static final String ASTERISK = "*";
    public static final String CLOSE_BRACKET = ")";
    public static final String DELIMITER = ",";
    public static final String DELIMITER_WITH_SPACE_SUFFIX = ", ";
    public static final String EQUALS = "=";
    public static final char EQUALS_CHAR = '=';
    public static final String FORMATTED_SEARCH_CONTROL_STRING = "{scope=%d, countLimit=%d, timeLimit=%d, returningAttributes=%s, derefLinkFlag=%b, returningObjFlag=%b}";
    public static final int LDAP_DEFAULT_PORT = 389;
    public static final int LDAPS_DEFAULT_PORT = 636;
    public static final String LDAP_DN_REGEX = "(?<!\\\\),";
    public static final String LDAP_FILTER_REGEX = "(?i)([a-zA-Z0-9_.\\-:]+)([:~><]?=)((\"[^\"]*\")|[^)]+)";
    public static final String LDAP_PROVIDER_URL_SPLIT_REGEX = "\\s+";
    public static final String LDAP_SCHEME_URL_REGEX = "(?i)^(ldap|ldaps)://.*";
    public static final String LDAP_DEFAULT_SCHEME_PREFIX = "ldap://";
    public static final String LDAPS_SCHEME = "ldaps";
    public static final String MASKED_VALUE = "***";
    public static final String MASKING_ATTRIBUTE_ERROR_MESSAGE = "error-masking-attributes";
    public static final String NO_SEARCH_CONTROLS = "no-search-controls";
    public static final String OPEN_BRACKET = "(";
    public static final String PEER_SERVICE_VALUE = "ldap";

    // Traced LDAP method names used in span naming.
    public static final String LDAP_EXTENDED_OPERATION_METHOD = "extendedOperation";
    public static final String LDAP_NEW_INSTANCE_METHOD = "newInstance";
    public static final String LDAP_RECONNECT_METHOD = "reconnect";
    public static final String LDAP_GET_ATTRIBUTES_METHOD = "getAttributes";
    public static final String LDAP_MODIFY_ATTRIBUTES_METHOD = "modifyAttributes";
    public static final String LDAP_BIND_METHOD = "bind";
    public static final String LDAP_REBIND_METHOD = "rebind";
    public static final String LDAP_UNBIND_METHOD = "unbind";
    public static final String LDAP_RENAME_METHOD = "rename";
    public static final String LDAP_CREATE_SUBCONTEXT_METHOD = "createSubcontext";
    public static final String LDAP_GET_SCHEMA_METHOD = "getSchema";
    public static final String LDAP_GET_SCHEMA_CLASS_DEFINITION_METHOD = "getSchemaClassDefinition";
    public static final String LDAP_SEARCH_METHOD = "search";
    public static final String LDAP_LOOKUP_METHOD = "lookup";
    public static final String LDAP_DESTROY_SUBCONTEXT_METHOD = "destroySubcontext";
    public static final String LDAP_LOOKUP_LINK_METHOD = "lookupLink";
    public static final String LDAP_BUILD_START_TLS_METHOD = "buildStartTLS";
}
