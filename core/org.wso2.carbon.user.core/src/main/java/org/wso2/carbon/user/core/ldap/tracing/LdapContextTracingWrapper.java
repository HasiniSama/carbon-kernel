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
import io.opentelemetry.context.Scope;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.user.core.ldap.StartTlsResponseWrapper;

import java.util.Hashtable;
import javax.naming.AuthenticationException;
import javax.naming.Binding;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NameClassPair;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.ExtendedRequest;
import javax.naming.ldap.ExtendedResponse;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsResponse;

/**
 * A wrapper for {@link LdapContext} that instruments LDAP operations with OpenTelemetry tracing.
 *
 * <p>This class wraps an existing {@link LdapContext} instance and adds support for span creation around LDAP
 * operations such as search, bind, lookup, modify, etc. It also optionally manages the lifecycle of a
 * {@link StartTlsResponseWrapper} if the StartTLS protocol is enabled.
 */
public class LdapContextTracingWrapper implements LdapContext {

    private static final Log LOG = LogFactory.getLog(LdapContextTracingWrapper.class);
    private LdapContext ldapContext;
    private boolean isStartTlsEnabled;
    private StartTlsResponse startTlsResponse;
    private StartTlsResponseWrapper startTlsResponseWrapper;

    /**
     * Constructs a tracing wrapper around the given {@link LdapContext} for non-TLS connections.
     *
     * @param ldapContext The underlying {@link LdapContext} to be wrapped.
     */
    private LdapContextTracingWrapper(LdapContext ldapContext) {

        this.ldapContext = ldapContext;
        this.isStartTlsEnabled = false;
    }

    /**
     * Constructs a tracing wrapper around the given {@link LdapContext} with a StartTLS response object.
     *
     * @param ldapContext      The underlying {@link LdapContext} to be wrapped.
     * @param startTlsResponse The StartTLS response object associated with the secured LDAP connection.
     */
    public LdapContextTracingWrapper(LdapContext ldapContext, StartTlsResponse startTlsResponse) {

        this.ldapContext = ldapContext;
        this.isStartTlsEnabled = true;
        this.startTlsResponse = startTlsResponse;
        this.startTlsResponseWrapper = new StartTlsResponseWrapper(this.startTlsResponse);
        this.startTlsResponseWrapper.incrementReferenceCounter();
    }

    /**
     * Constructs a tracing wrapper around the given {@link LdapContext} using an existing
     * {@link StartTlsResponseWrapper}. This constructor is typically used when the context is derived from an existing
     * StartTLS-secured context.
     *
     * @param ldapContext             The underlying {@link LdapContext} to be wrapped.
     * @param startTlsResponseWrapper A previously initialized and reference-counted {@link StartTlsResponseWrapper}.
     */
    private LdapContextTracingWrapper(LdapContext ldapContext, StartTlsResponseWrapper startTlsResponseWrapper) {

        this.ldapContext = ldapContext;
        this.isStartTlsEnabled = true;
        this.startTlsResponseWrapper = startTlsResponseWrapper;
        this.startTlsResponseWrapper.incrementReferenceCounter();
    }

    /**
     * Returns the underlying {@link LdapContext} instance.
     *
     * @return the LDAP context used for directory operations.
     */
    public LdapContext getLdapContext() {

        return ldapContext;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse extendedOperation(ExtendedRequest request) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_EXTENDED_OPERATION_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            if (request != null && StringUtils.isNotBlank(request.getID())) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_EXTENDED_OPERATION_ID, request.getID());
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing extended operation: " + (request != null &&
                        StringUtils.isNotBlank(request.getID()) ? request.getID() : "null"));
            }

            ExtendedResponse response = ldapContext.extendedOperation(request);
            ldapTracingSpan.success();
            return response;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP extendedOperation failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public LdapContext newInstance(Control[] requestControls) throws NamingException {

        // Start the tracing span for the newInstance method.
        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_NEW_INSTANCE_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            if (requestControls != null) {
                // Log and set attributes for LDAP request controls.
                LDAPTracingUtil.addControlSpanAttributes(requestControls, span);
            }

            // Delegate the actual context instantiation.
            LdapContext newContext = ldapContext.newInstance(requestControls);
            ldapTracingSpan.success();

            if (LOG.isDebugEnabled()) {
                LOG.debug("Successfully created new LDAP context via newInstance.");
            }

            // Wrap the new context in a tracing wrapper if StartTLS is enabled.
            return isStartTlsEnabled ? new LdapContextTracingWrapper(newContext, startTlsResponseWrapper) :
                    new LdapContextTracingWrapper(newContext);

        } catch (NamingException namingException) {
            // Record exception details in the span before rethrowing.
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP newInstance failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * Initializes a new {@link InitialLdapContext} and wraps it with {@link LdapContextTracingWrapper} to enable
     * tracing. This method is used to instrument and trace the creation of LDAP contexts, particularly to distinguish
     * between user credential-based flows (e.g., login) and system-level background operations (e.g., user sync or
     * group fetch).
     *
     * <p>
     * Tracing details such as the operation type, authentication result, request controls, and principal DN are added
     * to the span. In case of authentication failures, relevant attributes are recorded for diagnostic purposes.
     * </p>
     *
     * @param environment        A {@link Hashtable} containing LDAP environment properties such as
     *                           {@code Context.INITIAL_CONTEXT_FACTORY}, {@code Context.PROVIDER_URL},
     *                           {@code Context.SECURITY_PRINCIPAL}, etc. Should also include
     *                           {@code LDAPTracingConstants.ATTR_ENV_CREDENTIAL_FLOW} (Boolean) if the operation is
     *                           part of a credential-based flow.
     * @param connectionControls An array of LDAP {@link Control} objects used during context creation. These are
     *                           optional and may be {@code null}.
     * @return A {@link LdapContext} wrapped with tracing instrumentation.
     * @throws NamingException         If an error occurs during context initialization.
     * @throws AuthenticationException If the bind fails due to invalid credentials.
     */
    public static LdapContext newInstance(Hashtable<?, ?> environment, Control[] connectionControls)
            throws NamingException {

        // Determine if this is a credential (user-authenticated) flow.
        boolean isCredentialFlow = Boolean.TRUE.equals(environment.get(LDAPTracingConstants.ENV_CREDENTIAL_FLOW));

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_NEW_INSTANCE_METHOD,
                environment);
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            // Set span attribute indicating the origin of the context.
            span.setAttribute(
                    LDAPTracingConstants.ATTR_LDAP_CONTEXT_ORIGIN,
                    isCredentialFlow ? LDAPTracingConstants.ATTR_LDAP_CONTEXT_ORIGIN_USER_VALUE :
                            LDAPTracingConstants.ATTR_LDAP_CONTEXT_ORIGIN_SYSTEM_VALUE
            );

            if (connectionControls != null) {
                LDAPTracingUtil.addControlSpanAttributes(connectionControls, span);
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Tracing static LDAP newInstance with context origin: " + (isCredentialFlow ?
                        "user" : "system"));
            }

            LdapContext context = new InitialLdapContext(environment, connectionControls);
            ldapTracingSpan.success();

            if (LOG.isDebugEnabled()) {
                LOG.debug("Successfully created InitialLdapContext.");
            }

            return new LdapContextTracingWrapper(context);

        } catch (AuthenticationException authenticationException) {
            // Special handling for invalid credentials (user login scenario).
            if (isCredentialFlow) {
                // Specific span attributes for failed user authentication.
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_AUTH_RESULT,
                        LDAPTracingConstants.ATTR_LDAP_AUTH_RESULT_INVALID_CREDENTIALS);
                Object principal = environment.get(Context.SECURITY_PRINCIPAL);

                if (principal != null) {
                    span.setAttribute(LDAPTracingConstants.ATTR_LDAP_USER_DN,
                            LDAPTracingUtil.maskLdapString(principal.toString()));
                }

                if (LOG.isDebugEnabled()) {
                    LOG.debug("LDAP AuthenticationException (invalid credentials) for principal: " + principal);
                }
            } else {
                // System-level bind failure.
                ldapTracingSpan.error(authenticationException);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("System-level AuthenticationException during LDAP context creation: " +
                            authenticationException.getMessage(), authenticationException);
                }
            }
            throw authenticationException;

        } catch (NamingException namingException) {
            // Log and record generic naming exception.
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP context creation failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void reconnect(Control[] connectionControls) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_RECONNECT_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            if (connectionControls != null) {
                LDAPTracingUtil.addControlSpanAttributes(connectionControls, span);
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP reconnect called with " + (connectionControls != null ?
                        connectionControls.length : 0) + " connection controls.");
            }

            ldapContext.reconnect(connectionControls);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP reconnect failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Control[] getConnectControls() throws NamingException {

        // Tracing is skipped: retrieves client-supplied connection controls; does not involve network calls.
        return ldapContext.getConnectControls();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Control[] getRequestControls() throws NamingException {

        // Tracing is skipped: retrieves currently set request controls; purely local accessor.
        return ldapContext.getRequestControls();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setRequestControls(Control[] requestControls) throws NamingException {

        // Tracing is skipped: sets request controls for future LDAP operations; no immediate external interaction.
        ldapContext.setRequestControls(requestControls);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Control[] getResponseControls() throws NamingException {

        // Tracing is skipped: returns response controls from the last LDAP operation; no network activity here.
        return ldapContext.getResponseControls();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Attributes getAttributes(Name name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_GET_ATTRIBUTES_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Fetching LDAP attributes for Name-based DN.");
            }

            Attributes result = ldapContext.getAttributes(name);
            ldapTracingSpan.success();
            return result;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP getAttributes failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Attributes getAttributes(String name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_GET_ATTRIBUTES_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Fetching LDAP attributes for String-based DN.");
            }

            Attributes result = ldapContext.getAttributes(name);
            ldapTracingSpan.success();
            return result;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP getAttributes failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Attributes getAttributes(Name name, String[] attrIds) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_GET_ATTRIBUTES_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));
            if (attrIds != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_ATTRS, String.join(LDAPTracingConstants.DELIMITER,
                        attrIds));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Fetching LDAP attributes for Name-based DN with " + (attrIds != null ? attrIds.length :
                        0) + " requested attributes.");
            }

            Attributes result = ldapContext.getAttributes(name, attrIds);
            ldapTracingSpan.success();
            return result;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP getAttributes failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Attributes getAttributes(String name, String[] attrIds) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_GET_ATTRIBUTES_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));
            if (attrIds != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_ATTRS, String.join(LDAPTracingConstants.DELIMITER,
                        attrIds));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Fetching LDAP attributes for String-based DN with " + (attrIds != null ? attrIds.length :
                        0) + " requested attributes.");
            }

            Attributes result = ldapContext.getAttributes(name, attrIds);
            ldapTracingSpan.success();
            return result;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP getAttributes failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void modifyAttributes(Name name, int mod_op, Attributes attrs) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_MODIFY_ATTRIBUTES_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_MODIFY_OPERATION, mod_op);
            if (attrs != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_ATTRS, LDAPTracingUtil.maskAttributes(attrs));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Modifying LDAP attributes for Name-based DN with operation: " + mod_op);
            }

            ldapContext.modifyAttributes(name, mod_op, attrs);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP modifyAttributes failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void modifyAttributes(String name, int mod_op, Attributes attrs) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_MODIFY_ATTRIBUTES_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_MODIFY_OPERATION, mod_op);
            if (attrs != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_ATTRS, LDAPTracingUtil.maskAttributes(attrs));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Modifying LDAP attributes for String-based DN with operation: " + mod_op);
            }

            ldapContext.modifyAttributes(name, mod_op, attrs);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP modifyAttributes failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void modifyAttributes(Name name, ModificationItem[] mods) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_MODIFY_ATTRIBUTES_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_MODIFICATION_ITEM_COUNT, mods != null ? mods.length : 0);
            if (mods != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_MODIFICATION_ITEMS,
                        LDAPTracingUtil.maskModificationItems(mods));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Modifying LDAP attributes for Name-based DN with " + (mods != null ? mods.length : 0) +
                        " modification items.");
            }

            ldapContext.modifyAttributes(name, mods);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP modifyAttributes failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void modifyAttributes(String name, ModificationItem[] mods) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_MODIFY_ATTRIBUTES_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_MODIFICATION_ITEM_COUNT, mods != null ? mods.length : 0);
            if (mods != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_MODIFICATION_ITEMS,
                        LDAPTracingUtil.maskModificationItems(mods));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Modifying LDAP attributes for String-based DN with " + (mods != null ? mods.length : 0) +
                        " modification items.");
            }

            ldapContext.modifyAttributes(name, mods);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP modifyAttributes failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void bind(Name name, Object obj, Attributes attrs) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_BIND_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            LDAPTracingUtil.addBindRebindSpanData(name.toString(), obj, attrs, span);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Performing LDAP bind for Name-based DN.");
            }

            ldapContext.bind(name, obj, attrs);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP bind failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void bind(String name, Object obj, Attributes attrs) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_BIND_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            LDAPTracingUtil.addBindRebindSpanData(name, obj, attrs, span);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Performing LDAP bind for String-based DN.");
            }

            ldapContext.bind(name, obj, attrs);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP bind failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void rebind(Name name, Object obj, Attributes attrs) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_REBIND_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            LDAPTracingUtil.addBindRebindSpanData(name.toString(), obj, attrs, span);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Performing LDAP rebind for Name-based DN.");
            }

            ldapContext.rebind(name, obj, attrs);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP rebind failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void rebind(String name, Object obj, Attributes attrs) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_REBIND_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            LDAPTracingUtil.addBindRebindSpanData(name, obj, attrs, span);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Performing LDAP rebind for String-based DN.");
            }

            ldapContext.rebind(name, obj, attrs);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP rebind failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DirContext createSubcontext(Name name, Attributes attrs) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_CREATE_SUBCONTEXT_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));
            if (attrs != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_ATTRS, LDAPTracingUtil.maskAttributes(attrs));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Creating LDAP subcontext for Name-based DN.");
            }

            DirContext ctx = ldapContext.createSubcontext(name, attrs);
            ldapTracingSpan.success();
            return isStartTlsEnabled ? new LdapContextTracingWrapper((LdapContext) ctx, startTlsResponseWrapper) :
                    new LdapContextTracingWrapper((LdapContext) ctx);
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP createSubcontext failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DirContext createSubcontext(String name, Attributes attrs) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_CREATE_SUBCONTEXT_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));
            if (attrs != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_ATTRS, LDAPTracingUtil.maskAttributes(attrs));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Creating LDAP subcontext for String-based DN.");
            }

            DirContext ctx = ldapContext.createSubcontext(name, attrs);
            ldapTracingSpan.success();
            return isStartTlsEnabled ? new LdapContextTracingWrapper((LdapContext) ctx, startTlsResponseWrapper) :
                    new LdapContextTracingWrapper((LdapContext) ctx);
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP createSubcontext failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DirContext getSchema(Name name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_GET_SCHEMA_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Fetching LDAP schema for Name-based DN.");
            }

            DirContext ctx = ldapContext.getSchema(name);
            ldapTracingSpan.success();
            return isStartTlsEnabled ? new LdapContextTracingWrapper((LdapContext) ctx, startTlsResponseWrapper) :
                    new LdapContextTracingWrapper((LdapContext) ctx);
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP getSchema failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DirContext getSchema(String name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_GET_SCHEMA_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Fetching LDAP schema for String-based DN.");
            }

            DirContext ctx = ldapContext.getSchema(name);
            ldapTracingSpan.success();
            return isStartTlsEnabled ? new LdapContextTracingWrapper((LdapContext) ctx, startTlsResponseWrapper) :
                    new LdapContextTracingWrapper((LdapContext) ctx);
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP getSchema failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DirContext getSchemaClassDefinition(Name name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(
                LDAPTracingConstants.LDAP_GET_SCHEMA_CLASS_DEFINITION_METHOD, ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Fetching LDAP schema class definition for Name-based DN.");
            }

            DirContext ctx = ldapContext.getSchemaClassDefinition(name);
            ldapTracingSpan.success();
            return isStartTlsEnabled ? new LdapContextTracingWrapper((LdapContext) ctx, startTlsResponseWrapper) :
                    new LdapContextTracingWrapper((LdapContext) ctx);
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP getSchemaClassDefinition failed with NamingException: " +
                        namingException.getMessage(), namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DirContext getSchemaClassDefinition(String name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(
                LDAPTracingConstants.LDAP_GET_SCHEMA_CLASS_DEFINITION_METHOD, ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Fetching LDAP schema class definition for String-based DN.");
            }

            DirContext ctx = ldapContext.getSchemaClassDefinition(name);
            ldapTracingSpan.success();
            return isStartTlsEnabled ? new LdapContextTracingWrapper((LdapContext) ctx, startTlsResponseWrapper) :
                    new LdapContextTracingWrapper((LdapContext) ctx);
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP getSchemaClassDefinition failed with NamingException: " +
                        namingException.getMessage(), namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NamingEnumeration<SearchResult> search(Name name, Attributes matchingAttributes,
                                                  String[] attributesToReturn) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_SEARCH_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));
            if (matchingAttributes != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_MATCHING_ATTRS, LDAPTracingUtil.maskAttributes(
                        matchingAttributes));
            }
            if (attributesToReturn != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_RETURN_ATTRS, String.join(
                        LDAPTracingConstants.DELIMITER, attributesToReturn));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP search: Name-based DN with matching attributes and return attributes.");
            }

            NamingEnumeration<SearchResult> results = ldapContext.search(name, matchingAttributes, attributesToReturn);
            ldapTracingSpan.success();
            return results;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP search failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NamingEnumeration<SearchResult> search(String name, Attributes matchingAttributes,
                                                  String[] attributesToReturn) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_SEARCH_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));
            if (matchingAttributes != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_MATCHING_ATTRS, LDAPTracingUtil.maskAttributes(
                        matchingAttributes));
            }
            if (attributesToReturn != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_RETURN_ATTRS, String.join(
                        LDAPTracingConstants.DELIMITER, attributesToReturn));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP search: String-based DN with matching attributes and return attributes.");
            }

            NamingEnumeration<SearchResult> results = ldapContext.search(name, matchingAttributes, attributesToReturn);
            ldapTracingSpan.success();
            return results;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP search failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NamingEnumeration<SearchResult> search(Name name, Attributes matchingAttributes) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_SEARCH_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));
            if (matchingAttributes != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_MATCHING_ATTRS, LDAPTracingUtil.maskAttributes(
                        matchingAttributes));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP search: Name-based DN with matching attributes.");
            }

            NamingEnumeration<SearchResult> results = ldapContext.search(name, matchingAttributes);
            ldapTracingSpan.success();
            return results;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP search failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NamingEnumeration<SearchResult> search(String name, Attributes matchingAttributes) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_SEARCH_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));
            if (matchingAttributes != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_MATCHING_ATTRS, LDAPTracingUtil.maskAttributes(
                        matchingAttributes));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP search: String-based DN with matching attributes.");
            }

            NamingEnumeration<SearchResult> results = ldapContext.search(name, matchingAttributes);
            ldapTracingSpan.success();
            return results;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP search failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NamingEnumeration<SearchResult> search(Name name, String filter, SearchControls cons)
            throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_SEARCH_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_FILTER, LDAPTracingUtil.maskLdapString(filter));
            if (cons != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_SEARCH_CONTROLS,
                        LDAPTracingUtil.formatSearchControls(cons));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP search: Name-based DN with filter and search controls.");
            }

            NamingEnumeration<SearchResult> results = ldapContext.search(name, filter, cons);
            ldapTracingSpan.success();
            return results;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP search failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NamingEnumeration<SearchResult> search(String name, String filter, SearchControls cons)
            throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_SEARCH_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_FILTER, LDAPTracingUtil.maskLdapString(filter));
            if (cons != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_SEARCH_CONTROLS,
                        LDAPTracingUtil.formatSearchControls(cons));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP search: String-based DN with filter and search controls.");
            }

            NamingEnumeration<SearchResult> results = ldapContext.search(name, filter, cons);
            ldapTracingSpan.success();
            return results;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP search failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NamingEnumeration<SearchResult> search(Name name, String filterExpr, Object[] filterArgs,
                                                  SearchControls cons) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_SEARCH_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_FILTER_EXPRESSION,
                    LDAPTracingUtil.maskLdapString(filterExpr));
            if (filterArgs != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_FILTER_ARGS_LENGTH, filterArgs.length);
            }
            if (cons != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_SEARCH_CONTROLS,
                        LDAPTracingUtil.formatSearchControls(cons));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP search: Name-based DN with filter expression, arguments, and search " +
                        "controls.");
            }

            NamingEnumeration<SearchResult> results = ldapContext.search(name, filterExpr, filterArgs, cons);
            ldapTracingSpan.success();
            return results;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP search failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NamingEnumeration<SearchResult> search(String name, String filterExpr, Object[] filterArgs,
                                                  SearchControls cons) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_SEARCH_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_FILTER_EXPRESSION,
                    LDAPTracingUtil.maskLdapString(filterExpr));
            if (filterArgs != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_FILTER_ARGS_LENGTH, filterArgs.length);
            }
            if (cons != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_SEARCH_CONTROLS,
                        LDAPTracingUtil.formatSearchControls(cons));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP search: String-based DN with filter expression, arguments, and search " +
                        "controls.");
            }

            NamingEnumeration<SearchResult> results = ldapContext.search(name, filterExpr, filterArgs, cons);
            ldapTracingSpan.success();
            return results;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP search failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object lookup(Name name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_LOOKUP_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP lookup: Name-based DN.");
            }

            Object result = ldapContext.lookup(name);
            ldapTracingSpan.success();

            return isStartTlsEnabled ? new LdapContextTracingWrapper((LdapContext) result, startTlsResponseWrapper) :
                    new LdapContextTracingWrapper((LdapContext) result);

        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP lookup failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object lookup(String name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_LOOKUP_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP lookup: String-based DN.");
            }

            Object result = ldapContext.lookup(name);
            ldapTracingSpan.success();

            return isStartTlsEnabled ? new LdapContextTracingWrapper((LdapContext) result, startTlsResponseWrapper) :
                    new LdapContextTracingWrapper((LdapContext) result);

        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP lookup failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void bind(Name name, Object obj) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_BIND_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));
            // Log the class name of the object being bound, if available.
            if (obj != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_OBJECT_CLASS, obj.getClass().getName());
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP bind: Name-based DN without attributes.");
            }

            ldapContext.bind(name, obj);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP bind failed with NamingException: " + namingException.getMessage(), namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void bind(String name, Object obj) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_BIND_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));
            // Log the class name of the object being bound, if available.
            if (obj != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_OBJECT_CLASS, obj.getClass().getName());
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP bind: String-based DN without attributes.");
            }

            ldapContext.bind(name, obj);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP bind failed with NamingException: " + namingException.getMessage(), namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void rebind(Name name, Object obj) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_REBIND_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));
            // Log the class name of the object being bound, if available.
            if (obj != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_OBJECT_CLASS, obj.getClass().getName());
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP rebind: Name-based DN without attributes.");
            }

            ldapContext.rebind(name, obj);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP rebind failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void rebind(String name, Object obj) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_REBIND_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));
            // Log the class name of the object being bound, if available.
            if (obj != null) {
                span.setAttribute(LDAPTracingConstants.ATTR_LDAP_OBJECT_CLASS, obj.getClass().getName());
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP rebind: String-based DN without attributes.");
            }

            ldapContext.rebind(name, obj);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP rebind failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void unbind(Name name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_UNBIND_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP unbind: Name-based DN.");
            }

            ldapContext.unbind(name);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP unbind failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void unbind(String name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_UNBIND_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP unbind: String-based DN.");
            }

            ldapContext.unbind(name);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP unbind failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void rename(Name oldName, Name newName) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_RENAME_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN_OLD, LDAPTracingUtil.maskLdapString(
                    oldName.toString()));
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN_NEW, LDAPTracingUtil.maskLdapString(
                    newName.toString()));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP rename: Name-based DNs.");
            }

            ldapContext.rename(oldName, newName);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP rename failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void rename(String oldName, String newName) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_RENAME_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN_OLD, LDAPTracingUtil.maskLdapString(oldName));
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN_NEW, LDAPTracingUtil.maskLdapString(newName));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP rename: String-based DNs.");
            }

            ldapContext.rename(oldName, newName);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP rename failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NamingEnumeration<NameClassPair> list(Name name) throws NamingException {

        // Tracing is skipped: purely navigational, returns names within a context — does not access or modify data.
        return ldapContext.list(name);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NamingEnumeration<NameClassPair> list(String name) throws NamingException {

        // Tracing is skipped: purely navigational, returns names within a context — does not access or modify data.
        return ldapContext.list(name);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NamingEnumeration<Binding> listBindings(Name name) throws NamingException {

        // Tracing is skipped: slightly heavier than list(), but still structural — returns name + bound object, no
        // attribute/data access.
        return ldapContext.listBindings(name);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NamingEnumeration<Binding> listBindings(String name) throws NamingException {

        // Tracing is skipped: slightly heavier than list(), but still structural — returns name + bound object, no
        // attribute/data access.
        return ldapContext.listBindings(name);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void destroySubcontext(Name name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_DESTROY_SUBCONTEXT_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP destroySubcontext: Name-based DN.");
            }

            ldapContext.destroySubcontext(name);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP destroySubcontext failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void destroySubcontext(String name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_DESTROY_SUBCONTEXT_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP destroySubcontext: String-based DN.");
            }

            ldapContext.destroySubcontext(name);
            ldapTracingSpan.success();
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP destroySubcontext failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Context createSubcontext(Name name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_CREATE_SUBCONTEXT_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP createSubcontext: Name-based DN.");
            }

            LdapContext ctx = (LdapContext) ldapContext.createSubcontext(name);
            ldapTracingSpan.success();
            return isStartTlsEnabled ? new LdapContextTracingWrapper(ctx, startTlsResponseWrapper) : new
                    LdapContextTracingWrapper(ctx);
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP createSubcontext failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Context createSubcontext(String name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_CREATE_SUBCONTEXT_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP createSubcontext: String-based DN.");
            }

            LdapContext ctx = (LdapContext) ldapContext.createSubcontext(name);
            ldapTracingSpan.success();
            return isStartTlsEnabled ? new LdapContextTracingWrapper(ctx, startTlsResponseWrapper) : new
                    LdapContextTracingWrapper(ctx);
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP createSubcontext failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object lookupLink(Name name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_LOOKUP_LINK_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name.toString()));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP lookupLink: Name-based DN.");
            }

            Object result = ldapContext.lookupLink(name);
            ldapTracingSpan.success();
            return result;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP lookupLink failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object lookupLink(String name) throws NamingException {

        LDAPTracingSpan ldapTracingSpan = LDAPTracingSpan.start(LDAPTracingConstants.LDAP_LOOKUP_LINK_METHOD,
                ldapContext.getEnvironment());
        Span span = ldapTracingSpan.span();

        try (Scope ignored = span.makeCurrent()) {
            span.setAttribute(LDAPTracingConstants.ATTR_LDAP_DN, LDAPTracingUtil.maskLdapString(name));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing LDAP lookupLink: String-based DN.");
            }

            Object result = ldapContext.lookupLink(name);
            ldapTracingSpan.success();
            return result;
        } catch (NamingException namingException) {
            ldapTracingSpan.error(namingException);
            if (LOG.isDebugEnabled()) {
                LOG.debug("LDAP lookupLink failed with NamingException: " + namingException.getMessage(),
                        namingException);
            }
            throw namingException;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NameParser getNameParser(Name name) throws NamingException {

        // Tracing is skipped: retrieves a local name parser; no network call or state change occurs.
        return ldapContext.getNameParser(name);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NameParser getNameParser(String name) throws NamingException {

        // Tracing is skipped: retrieves a local name parser; no network call or state change occurs.
        return ldapContext.getNameParser(name);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Name composeName(Name name, Name prefix) throws NamingException {

        // Tracing is skipped: composes a name locally using string manipulation logic; no external operations.
        return ldapContext.composeName(name, prefix);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String composeName(String name, String prefix) throws NamingException {

        // Tracing is skipped: composes a name locally using string manipulation logic; no external operations.
        return ldapContext.composeName(name, prefix);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object addToEnvironment(String propName, Object propVal) throws NamingException {

        // Tracing is skipped: modifies local environment properties for this context instance; does not perform I/O.
        return ldapContext.addToEnvironment(propName, propVal);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object removeFromEnvironment(String propName) throws NamingException {

        // Tracing is skipped: removes a local environment property; purely internal configuration logic.
        return ldapContext.removeFromEnvironment(propName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hashtable<?, ?> getEnvironment() throws NamingException {

        // Tracing is skipped: returns the local environment used to create the context; no remote access involved.
        return ldapContext.getEnvironment();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws NamingException {

        // Tracing is skipped: closes local resources associated with the context; no remote communication.
        try {
            if (isStartTlsEnabled && startTlsResponseWrapper != null) {
                startTlsResponseWrapper.close();
            }
        } finally {
            ldapContext.close();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getNameInNamespace() throws NamingException {

        // Tracing is skipped: retrieves the distinguished name of this context within the directory namespace;
        // no network call.
        return ldapContext.getNameInNamespace();
    }
}
