package com.cleansightsolutions.keycloak.protocol.oidc.mappers;

import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.organization.OrganizationProvider;

import static org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN;
import static org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper.INCLUDE_IN_INTROSPECTION;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class OrganizationAudienceMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper {

    public static final String PROVIDER_ID = "oidc-organization-audience-mapper";

    /*
     * A config which keycloak uses to display a generic dialog to configure the token.
     */
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, OrganizationAudienceMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Organization Audience Mapper";
    }

    @Override
    public String getHelpText() {
        return "Adds 'aud' (audience) claims for each audience attribute of every organization the user is associated with.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession keycloakSession,
                                            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        boolean shouldUseLightweightToken = getShouldUseLightweightToken(keycloakSession);
        boolean includeInAccessToken = shouldUseLightweightToken ?  OIDCAttributeMapperHelper.includeInLightweightAccessToken(mappingModel) : includeInAccessToken(mappingModel);
        if (!includeInAccessToken){
            return token;
        }
        setAudience(token, userSession, keycloakSession);
        return token;
    }

    private boolean includeInAccessToken(ProtocolMapperModel mappingModel) {
        String includeInAccessToken = mappingModel.getConfig().get(INCLUDE_IN_ACCESS_TOKEN);

        // Backwards compatibility
        if (includeInAccessToken == null) {
            return true;
        }

        return "true".equals(includeInAccessToken);
    }

    @Override
    public AccessToken transformIntrospectionToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession keycloakSession,
                                                   UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        if (!includeInIntrospection(mappingModel)) {
            return token;
        }

        setAudience(token, userSession, keycloakSession);
        return token;
    }

    private boolean includeInIntrospection(ProtocolMapperModel mappingModel) {
        String includeInIntrospection = mappingModel.getConfig().get(INCLUDE_IN_INTROSPECTION);

        // Backwards compatibility
        if (includeInIntrospection == null) {
            return true;
        }

        return "true".equals(includeInIntrospection);
    }

    private void setAudience(AccessToken token, UserSessionModel userSession, KeycloakSession session) {
        UserModel user = userSession.getUser();
        OrganizationProvider orgProvider = session.getProvider(OrganizationProvider.class);

        if (orgProvider == null) {
            return;
        }

        // Only include organizations that define an 'audience' attribute
        List<String> audiencesFromOrganizations = orgProvider.getByMember(user)
                .map(orgModel -> {
                    Map<String, List<String>> attributes = orgModel.getAttributes();

                    if(attributes == null) {
                        return null;
                    }

                    List<String> vals = attributes.get("audience");

                    if(vals == null) {
                        return null;
                    }

                    String v = vals.get(0); // Use the first option

                    return (!(v == null | v.isBlank())) ? v : null;
                })
                .filter(Objects::nonNull)
                .filter(aud -> !aud.isBlank())
                .collect(Collectors.toList());

        if (audiencesFromOrganizations.isEmpty()) {
            return;
        }

        // Merge with existing aud claim if present
        Set<String> completeAudiences = new HashSet<>(audiencesFromOrganizations);

        for (String audience : completeAudiences) {
            token.addAudience(audience);
        }
    }

     public static ProtocolMapperModel createClaimMapper(String name, boolean accessToken, boolean introspectionEndpoint) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap<>();
        if (accessToken) {
            config.put(INCLUDE_IN_ACCESS_TOKEN, "true");
        } else {
            config.put(INCLUDE_IN_ACCESS_TOKEN, "false");
        }
        if (introspectionEndpoint) {
            config.put(INCLUDE_IN_INTROSPECTION, "true");
        } else {
            config.put(INCLUDE_IN_INTROSPECTION, "false");
        }
        mapper.setConfig(config);
        return mapper;
    }
}
