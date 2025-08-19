package com.oneground.keycloak.introspection;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for creating Custom JWT Token Introspection Provider instances.
 * This creates a REST endpoint for custom JWT token introspection.
 */
public class CustomJwtIntrospectionProviderFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "zgw-token-introspection";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new CustomJwtIntrospectionProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // No initialization needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization needed
    }

    @Override
    public void close() {
        // No cleanup needed
    }
}
