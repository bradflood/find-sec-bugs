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

import org.neo4j.graphdb.Label;

public class GraphLabels {

    public static final Label LABEL_FUNCTION  = Label.label("Function");
    public static final Label LABEL_CLASS     = Label.label("Class");
    public static final Label LABEL_INTERFACE = Label.label("Interface");
    public static final Label LABEL_VARIABLE  = Label.label("Variable");

}
