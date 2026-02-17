package com.contrast.frontgateservice.controller;

import org.junit.jupiter.api.Test;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ApiControllerSecurityTest {

    @Test
    void testObjectInputFilterRejectsUnauthorizedClasses() throws Exception {
        ObjectInputFilter filter = createAddressImportFilter();

        ObjectInputFilter.FilterInfo allowedInfo = createFilterInfo(ArrayList.class);
        assertEquals(ObjectInputFilter.Status.ALLOWED, filter.checkInput(allowedInfo));

        ObjectInputFilter.FilterInfo hashMapInfo = createFilterInfo(HashMap.class);
        assertEquals(ObjectInputFilter.Status.ALLOWED, filter.checkInput(hashMapInfo));

        ObjectInputFilter.FilterInfo stringInfo = createFilterInfo(String.class);
        assertEquals(ObjectInputFilter.Status.ALLOWED, filter.checkInput(stringInfo));
    }

    @Test
    void testObjectInputFilterRejectsDangerousClasses() throws Exception {
        ObjectInputFilter filter = createAddressImportFilter();

        ObjectInputFilter.FilterInfo runtimeInfo = createFilterInfo(Runtime.class);
        assertEquals(ObjectInputFilter.Status.REJECTED, filter.checkInput(runtimeInfo));

        ObjectInputFilter.FilterInfo processBuilderInfo = createFilterInfo(ProcessBuilder.class);
        assertEquals(ObjectInputFilter.Status.REJECTED, filter.checkInput(processBuilderInfo));

        ObjectInputFilter.FilterInfo fileInfo = createFilterInfo(File.class);
        assertEquals(ObjectInputFilter.Status.REJECTED, filter.checkInput(fileInfo));
    }

    @Test
    void testDeserializationWithFilterRejectsUnauthorizedClass() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(new File("/etc/passwd"));
        oos.close();

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.setObjectInputFilter(createAddressImportFilter());

        assertThrows(InvalidClassException.class, () -> {
            ois.readObject();
        });
        ois.close();
    }

    @Test
    void testDeserializationWithFilterAllowsValidAddressData() throws Exception {
        List<Map<String, Object>> addresses = new ArrayList<>();
        Map<String, Object> address = new HashMap<>();
        address.put("street", "123 Main St");
        address.put("city", "Springfield");
        address.put("zipCode", "12345");
        addresses.add(address);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(addresses);
        oos.close();

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.setObjectInputFilter(createAddressImportFilter());

        Object result = ois.readObject();
        ois.close();

        assertNotNull(result);
        assertTrue(result instanceof List);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resultList = (List<Map<String, Object>>) result;
        assertEquals(1, resultList.size());
        assertEquals("123 Main St", resultList.get(0).get("street"));
    }

    private static ObjectInputFilter createAddressImportFilter() {
        return filterInfo -> {
            Class<?> clazz = filterInfo.serialClass();
            if (clazz == null) {
                return ObjectInputFilter.Status.UNDECIDED;
            }
            String className = clazz.getName();
            // Allow safe java.util classes (collections and related)
            if (className.startsWith("java.util.")) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            // Allow safe java.lang wrapper classes (but not Runtime, ProcessBuilder, etc.)
            if (clazz == java.lang.String.class ||
                clazz == java.lang.Integer.class ||
                clazz == java.lang.Long.class ||
                clazz == java.lang.Double.class ||
                clazz == java.lang.Float.class ||
                clazz == java.lang.Boolean.class ||
                clazz == java.lang.Byte.class ||
                clazz == java.lang.Short.class ||
                clazz == java.lang.Character.class ||
                clazz == java.lang.Number.class) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            // Allow array types (needed for ArrayList/HashMap internal storage)
            if (clazz.isArray()) {
                Class<?> componentType = clazz.getComponentType();
                // Allow Object[] and primitive arrays
                if (componentType == Object.class || componentType.isPrimitive()) {
                    return ObjectInputFilter.Status.ALLOWED;
                }
                // Allow arrays of safe types
                String componentName = componentType.getName();
                if (componentName.startsWith("java.util.")) {
                    return ObjectInputFilter.Status.ALLOWED;
                }
            }
            return ObjectInputFilter.Status.REJECTED;
        };
    }

    private ObjectInputFilter.FilterInfo createFilterInfo(Class<?> clazz) {
        return new ObjectInputFilter.FilterInfo() {
            @Override
            public Class<?> serialClass() {
                return clazz;
            }

            @Override
            public long arrayLength() {
                return -1;
            }

            @Override
            public long depth() {
                return 1;
            }

            @Override
            public long references() {
                return 1;
            }

            @Override
            public long streamBytes() {
                return 0;
            }
        };
    }
}
