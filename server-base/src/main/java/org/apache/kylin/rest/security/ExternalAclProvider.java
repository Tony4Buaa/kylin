/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
package org.apache.kylin.rest.security;

import java.util.List;

import org.apache.kylin.common.KylinConfig;
import org.apache.kylin.common.util.ClassUtil;
import org.apache.kylin.common.util.Pair;

/**
 */
abstract public class ExternalAclProvider {

    private static boolean inited = false;
    private static ExternalAclProvider singleton = null;

    public static ExternalAclProvider getInstance() {
        if (inited)
            return singleton;

        synchronized (ExternalAclProvider.class) {
            if (inited)
                return singleton;

            String cls = KylinConfig.getInstanceFromEnv().getExternalAclProvider();
            if (cls != null && cls.length() > 0) {
                singleton = (ExternalAclProvider) ClassUtil.newInstance(cls);
                singleton.init();
            }

            inited = true;
            return singleton;
        }
    }

    // ============================================================================

    abstract public void init();

    /**
     * Checks if a user has permission on an entity.
     * @param user
     * @param userRoles
     * @param entityType String constants defined in AclEntityType 
     * @param entityUuid
     * @param permission
     * 
     * @return true if has permission
     */
    abstract public boolean checkPermission(String user, List<String> userRoles, //
            String entityType, String entityUuid, AclPermission permission);

    /**
     * Returns all granted permissions on specified entity.
     * 
     * @param entityType String constants defined in AclEntityType
     * @param entityUuid
     * @return a list of (user/role, permission)
     */
    abstract public List<Pair<String, AclPermission>> getAcl(String entityType, String entityUuid);

}
