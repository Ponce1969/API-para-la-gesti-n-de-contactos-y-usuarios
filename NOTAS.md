# Notas de desarrollo para App Statica

## Problemas resueltos

### Módulo de contactos

1. **Inconsistencia en la arquitectura del repositorio de contactos** ✅:
   - Problema: El servicio `ContactGroupService` intentaba usar métodos que no existían en el repositorio (`get_group_by_id`, `get_group_by_name`, etc.)
   - Solución implementada: Se creó una clase separada `ContactGroupRepository` con todos los métodos necesarios
   - Mejora adicional: Se eliminaron múltiples definiciones duplicadas de `ContactGroupRepository` que existían en el archivo

## Problemas pendientes

### Módulo de contactos

1. **Errores de tipado**:
   - Hay inconsistencias en los tipos de retorno entre el repositorio y el servicio
   - Se debe asegurar que las referencias a `DatabaseError` sean consistentes

2. **Pruebas unitarias**:
   - Implementar pruebas para `ContactRepository` y `ContactGroupRepository`
   - Asegurar cobertura de casos de éxito y error
