/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.authz.store;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ContextPreservingActionListener;
import org.elasticsearch.action.support.SubscribableListener;
import org.elasticsearch.cluster.metadata.ProjectId;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.util.set.Sets;
import org.elasticsearch.core.CheckedConsumer;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.logging.LogManager;
import org.elasticsearch.logging.Logger;
import org.elasticsearch.xpack.core.security.authz.permission.Role;
import org.elasticsearch.xpack.core.security.authz.store.RoleKey;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * Owns shared role resolutions and negative lookups for {@link CompositeRolesStore}.
 * <p>
 * Cache access runs under the monitor; role resolution and listener completion run outside it.
 * Reads hash and compare role keys outside the monitor, then use identity-based {@link InternedKey} tokens inside it.
 * <p>
 * Invalidations remove matching pending and completed roles; generations guard late negative-cache writes per project.
 */
final class GuardedRoleCaches {

    private static final Logger logger = LogManager.getLogger(GuardedRoleCaches.class);

    /** Carries cache metadata only until the built role is published to subscribers. */
    record RoleLoadResult(Role role, Set<String> missingRoles, boolean cacheable) {}

    /** Identifies invalidations that overlap a load. */
    private record Generation(long project, long global) {}

    private final ThreadContext threadContext;

    /**
     * A cache key that scopes another key to a project.
     */
    record ProjectScoped<T>(ProjectId projectId, T value) {
        ProjectScoped {
            Objects.requireNonNull(projectId);
        }
    }

    /**
     * The canonical token for a cached role key. It does not override {@code equals} or {@code hashCode}, so a lookup by token
     * under the monitor is an identity comparison. Two tokens for equal keys can only cost a cache miss, never serve the wrong role.
     */
    static final class InternedKey {
        private final ProjectScoped<RoleKey> key;

        private InternedKey(ProjectScoped<RoleKey> key) {
            this.key = key;
        }
    }

    /**
     * Maps each key in {@link #roles} to its token. Read without the monitor, but only modified under it, alongside {@link #roles},
     * so it holds exactly the keys of {@link #roles}. A reader can find a token whose role has just been removed; it then misses.
     */
    private final ConcurrentHashMap<ProjectScoped<RoleKey>, InternedKey> interned = new ConcurrentHashMap<>();

    // All fields below are guarded by this object's monitor
    private final Map<InternedKey, SubscribableListener<Role>> roles;
    private final Map<ProjectScoped<String>, Boolean> negativeLookups;
    private final Map<ProjectId, Long> projectGenerations = new HashMap<>();
    private long globalGeneration;

    /**
     * @param maximumRoles           the maximum number of cached roles, or a negative value for no limit
     * @param maximumNegativeLookups the maximum number of cached negative lookups, or a negative value for no limit
     * @param threadContext          the request context preserved for each subscriber
     */
    GuardedRoleCaches(int maximumRoles, int maximumNegativeLookups, ThreadContext threadContext) {
        this.threadContext = Objects.requireNonNull(threadContext);
        this.roles = leastRecentlyUsedMap(maximumRoles, token -> interned.remove(token.key, token));
        this.negativeLookups = leastRecentlyUsedMap(maximumNegativeLookups, key -> {});
    }

    /**
     * A map ordered by most recent access that drops its least recently used entry once it holds more than {@code maximumSize}
     * entries, passing its key to {@code onEvict}. A negative maximum means no limit; zero means nothing is ever retained.
     */
    private static <K, V> Map<K, V> leastRecentlyUsedMap(int maximumSize, Consumer<K> onEvict) {
        return new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                if (maximumSize >= 0 && size() > maximumSize) {
                    onEvict.accept(eldest.getKey());
                    return true;
                }
                return false;
            }
        };
    }

    private static <T extends ProjectScoped<?>> Predicate<T> eq(ProjectId projectId) {
        return key -> key.projectId().equals(projectId);
    }

    /**
     * Removes the cached roles whose keys match, together with their tokens.
     */
    private void removeRoles(Predicate<ProjectScoped<RoleKey>> predicate) {
        assert Thread.holdsLock(this);
        final Iterator<InternedKey> iterator = roles.keySet().iterator();
        while (iterator.hasNext()) {
            final InternedKey token = iterator.next();
            if (predicate.test(token.key)) {
                iterator.remove();
                interned.remove(token.key, token);
            }
        }
    }

    @Nullable
    SubscribableListener<Role> getRole(ProjectId projectId, RoleKey roleKey) {
        // Hashing and comparing the key happen here, outside the monitor
        final InternedKey token = interned.get(new ProjectScoped<>(projectId, roleKey));
        if (token == null) {
            return null;
        }
        synchronized (this) {
            return roles.get(token);
        }
    }

    /** Completes cache hits inline and pending loads on their completing thread, preserving the caller's context. */
    void getOrLoadRole(
        ProjectId projectId,
        RoleKey roleKey,
        CheckedConsumer<ActionListener<RoleLoadResult>, Exception> loader,
        ActionListener<Role> listener
    ) {
        final SubscribableListener<Role> sharedRoleListener = getOrLoadRole(projectId, roleKey, loader);
        sharedRoleListener.addListener(listener, EsExecutors.DIRECT_EXECUTOR_SERVICE, threadContext);
    }

    /** Shares a cached resolution or starts a load outside the cache monitor. */
    private SubscribableListener<Role> getOrLoadRole(
        ProjectId projectId,
        RoleKey roleKey,
        CheckedConsumer<ActionListener<RoleLoadResult>, Exception> loader
    ) {
        final SubscribableListener<Role> existing = getRole(projectId, roleKey);
        if (existing != null) {
            return existing;
        }
        final ProjectScoped<RoleKey> key = new ProjectScoped<>(projectId, roleKey);
        final SubscribableListener<Role> sharedRoleListener = new SubscribableListener<>();
        final Generation generation;
        final InternedKey token;
        synchronized (this) {
            token = interned.computeIfAbsent(key, InternedKey::new);
            final SubscribableListener<Role> current = roles.putIfAbsent(token, sharedRoleListener);
            if (current != null) {
                return current;
            }
            generation = generation(projectId);
        }
        // Complete in an empty context so subscribers retain only their own request headers.
        final ActionListener<RoleLoadResult> completionListener = new ContextPreservingActionListener<>(
            threadContext::newEmptyContext,
            ActionListener.wrap(result -> {
                if (result.cacheable() == false) {
                    removeRole(token, sharedRoleListener);
                } else if (result.missingRoles().isEmpty() == false) {
                    putMissingIfCurrent(generation, projectId, result.missingRoles());
                }
                sharedRoleListener.onResponse(result.role());
            }, e -> {
                removeRole(token, sharedRoleListener);
                sharedRoleListener.onFailure(e);
            })
        );
        // Stash caller authentication while retaining the project for shared role resolution.
        try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
            ActionListener.run(completionListener, loader);
        }
        return sharedRoleListener;
    }

    /** Removes only this resolution, leaving any replacement load intact. */
    private synchronized void removeRole(InternedKey token, SubscribableListener<Role> expected) {
        if (roles.remove(token, expected)) {
            interned.remove(token.key, token);
        }
    }

    synchronized boolean isKnownMissing(ProjectId projectId, String roleName) {
        // get rather than containsKey so that the lookup counts as an access for eviction purposes
        return negativeLookups.get(new ProjectScoped<>(projectId, roleName)) != null;
    }

    /** Captures the generation before any role source is consulted. */
    private Generation generation(ProjectId projectId) {
        assert Thread.holdsLock(this);
        return new Generation(projectGenerations.getOrDefault(projectId, 0L), globalGeneration);
    }

    /** Records missing names only if no invalidation has moved the observed generation. */
    private synchronized void putMissingIfCurrent(Generation observed, ProjectId projectId, Set<String> missing) {
        if (observed.equals(generation(projectId)) == false) {
            logger.trace(
                "not caching missing roles [{}] in project [{}] because the caches were invalidated during resolution",
                missing,
                projectId
            );
            return;
        }
        for (String name : missing) {
            negativeLookups.put(new ProjectScoped<>(projectId, name), Boolean.TRUE);
        }
    }

    synchronized void invalidateAll() {
        roles.clear();
        interned.clear();
        negativeLookups.clear();
        globalGeneration++;
    }

    synchronized void invalidateProject(ProjectId projectId) {
        removeRoles(eq(projectId));
        negativeLookups.keySet().removeIf(eq(projectId));
        projectGenerations.merge(projectId, 1L, Long::sum);
    }

    synchronized void removeProject(ProjectId projectId) {
        removeRoles(eq(projectId));
        negativeLookups.keySet().removeIf(eq(projectId));
        projectGenerations.remove(projectId);
        // Prevent old lookups from restoring negative entries after their project generation is forgotten.
        globalGeneration++;
    }

    synchronized void invalidateRole(ProjectId projectId, String role) {
        removeRoles(key -> key.projectId().equals(projectId) && key.value().getNames().contains(role));
        negativeLookups.remove(new ProjectScoped<>(projectId, role));
        projectGenerations.merge(projectId, 1L, Long::sum);
    }

    synchronized void invalidateClusterScopedRoles(Set<String> names) {
        removeRoles(key -> Sets.haveEmptyIntersection(key.value().getNames(), names) == false);
        negativeLookups.keySet().removeIf(key -> names.contains(key.value()));
        globalGeneration++;
    }

    // for testing
    synchronized List<ProjectScoped<RoleKey>> cachedRoleKeys() {
        return roles.keySet().stream().map(token -> token.key).toList();
    }

    // for testing
    int internedKeyCount() {
        return interned.size();
    }
}
