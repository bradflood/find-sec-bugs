/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */
package com.h3xstream.findsecbugs.graph.model;

import org.neo4j.graphdb.RelationshipType;

public enum RelTypes implements RelationshipType {

    /**
     * Describe the link between two variable state.
     * Example :
     *  - A value being passed to function argument.
     *  - A value being return from a function
     *  - A value that is assign to a field
     */
    TRANSFER,
}
