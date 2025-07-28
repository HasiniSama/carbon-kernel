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

package org.wso2.carbon.user.core.ldap;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.context.Scope;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.ldap.tracing.LDAPTracingConstants;
import org.wso2.carbon.user.core.ldap.tracing.LDAPTracingSpan;
import org.wso2.carbon.user.core.ldap.tracing.LdapContextTracingWrapper;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import java.io.IOException;
import java.util.Hashtable;

/**
 * Factory class for initializing LDAP contexts over StartTLS, applying authentication after securing the connection,
 * and optionally wrapping the context with tracing support. Note that most of the implementation was moved from the
 * {@link LdapContextWrapper} class.
 */
public class StartTlsLdapContextFactory {

    private static final Log LOG = LogFactory.getLog(StartTlsLdapContextFactory.class);

    /**
     * Initialize the LDAP context with secured connection by applying StartTLS extended operation.
     *
     * @param environment        environment used to create the initial Context.
     * @param connectionControls connection request controls for the initial context.
     * @param withTracing        if the ldap context should be wrapped with the tracing wrapper.
     * @return secured ldap connection context.
     * @throws NamingException    if a naming exception is encountered.
     * @throws UserStoreException if a user store related exception is encountered.
     */
    public static LdapContext build(Hashtable<?, ?> environment, Control[] connectionControls, boolean withTracing)
            throws NamingException, UserStoreException {

        if (withTracing) {
            LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_BUILD_START_TLS_METHOD,
                    environment);
            Span span = ldapTracingSpan.span();

            try (Scope ignored = span.makeCurrent()) {
                LdapContext ldapContext = createStartTlsSecuredLdapContext(environment, connectionControls, true);
                ldapTracingSpan.success();
                return ldapContext;
            } catch (Exception exception) {
                ldapTracingSpan.error();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("LDAP build start TLS failed with Exception: " + exception.getMessage(), exception);
                }
                throw exception;
            }
        } else {
            return createStartTlsSecuredLdapContext(environment, connectionControls, false);
        }
    }

    /**
     * Creates a secured LDAP context by initiating a StartTLS connection and wrapping it with the appropriate context
     * wrapper.
     * <p>
     * If tracing is enabled, the context is wrapped with a tracing-enabled wrapper; otherwise, a standard wrapper is used.
     * Performs authentication if credentials are provided in the environment.
     *
     * @param environment        the environment properties used to create the initial context.
     * @param connectionControls the connection controls to be used with the LDAP context.
     * @param withTracing        whether to enable tracing on the LDAP context.
     * @return the secured and appropriately wrapped LDAP context.
     * @throws NamingException    if an error occurs while creating or interacting with the LDAP context.
     * @throws UserStoreException if the StartTLS negotiation fails or authentication encounters issues.
     */
    private static LdapContext createStartTlsSecuredLdapContext(Hashtable<?, ?> environment,
                                                                Control[] connectionControls, boolean withTracing)
            throws UserStoreException, NamingException {

        Hashtable<String, Object> tempEnv = StartTlsLdapContextFactory.getEnvironmentForSecuredLdapInitialization(
                environment);
        LdapContext ldapContext = new InitialLdapContext(tempEnv, connectionControls);
        try {

            StartTlsResponse startTlsResponse = (StartTlsResponse) ldapContext.extendedOperation(new StartTlsRequest());
            startTlsResponse.negotiate();

            if (LOG.isDebugEnabled()) {
                LOG.debug("StartTLS connection established successfully with LDAP server");
            }

            if (withTracing) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Wrapping LDAP context with tracing-enabled context.");
                }

                LdapContextTracingWrapper ldapContextTracingWrapper = new LdapContextTracingWrapper(ldapContext,
                        startTlsResponse);
                performAuthenticationIfProvided(environment, ldapContextTracingWrapper.getLdapContext());

                return ldapContextTracingWrapper;
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Wrapping LDAP context with standard context (no tracing).");
                }

                LdapContextWrapper ldapContextWrapper = new LdapContextWrapper(ldapContext, startTlsResponse);
                performAuthenticationIfProvided(environment, ldapContextWrapper.getLdapContext());

                return ldapContextWrapper;
            }
        } catch (IOException e) {
            throw new UserStoreException("Unable to establish the StartTLS connection", e);
        }
    }

    /**
     * Get environment variables to initialize secured LDAP context.
     *
     * @param environment environment used to create the initial Context.
     * @return environment.
     */
    private static Hashtable<String, Object> getEnvironmentForSecuredLdapInitialization(Hashtable<?, ?> environment) {

        Hashtable<String, Object> tempEnv = new Hashtable<>();
        // Create a temp env for this particular connection by eliminating user credentials details from original env.
        for (Object key : environment.keySet()) {
            if (Context.SECURITY_PRINCIPAL.equals(key) || Context.SECURITY_CREDENTIALS.equals(key) ||
                    Context.SECURITY_AUTHENTICATION.equals(key)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Attribute " + key + " is skip adding to the environment for TLS LDAP initialization");
                }
            } else {
                tempEnv.put((String) key, environment.get(key));
            }
        }
        return tempEnv;
    }

    /**
     * Perform simple client authentication.
     *
     * @param environment environment used to create the initial Context.
     * @param ldapContext the ldap context to which attributes should be added.
     * @throws NamingException if a naming exception is encountered.
     */
    private static void performAuthenticationIfProvided(Hashtable<?, ?> environment, LdapContext ldapContext)
            throws NamingException {

        // Adding provided user credentials details one by one after TLS connection started.
        if (environment.containsKey(Context.SECURITY_AUTHENTICATION)) {
            ldapContext.addToEnvironment(Context.SECURITY_AUTHENTICATION,
                    environment.get(Context.SECURITY_AUTHENTICATION));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Attribute " + Context.SECURITY_AUTHENTICATION + " is added to the " +
                        "TLS LdapContext environment");
            }
        }
        if (environment.containsKey(Context.SECURITY_PRINCIPAL)) {
            ldapContext.addToEnvironment(Context.SECURITY_PRINCIPAL,
                    environment.get(Context.SECURITY_PRINCIPAL));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Attribute " + Context.SECURITY_PRINCIPAL + " is added to the " +
                        "TLS LdapContext environment");
            }
        }
        if (environment.containsKey(Context.SECURITY_CREDENTIALS)) {
            ldapContext.addToEnvironment(Context.SECURITY_CREDENTIALS,
                    environment.get(Context.SECURITY_CREDENTIALS));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Attribute " + Context.SECURITY_CREDENTIALS + " is added to the " +
                        "TLS LdapContext environment");
            }
        }

        /*
         * Verify whether the user is authenticated successfully.
         * {@link} https://docs.oracle.com/javase/jndi/tutorial/ldap/ext/src/StartTlsSimple.java
         */
        ldapContext.getAttributes("");
    }
}