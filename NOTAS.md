# Notas de desarrollo para App Statica

## Problemas pendientes

### Módulo de contactos

1. **Inconsistencia en la arquitectura del repositorio de contactos**:
   - El servicio `ContactGroupService` intenta usar métodos que no existen en el repositorio (`get_group_by_id`, `get_group_by_name`, etc.)
   - Opciones de solución:
     - Implementar los métodos faltantes en `ContactRepository` para manejar grupos
     - Crear una clase separada `ContactGroupRepository` con los métodos necesarios

2. **Errores de tipado**:
   - Hay inconsistencias en los tipos de retorno entre el repositorio y el servicio
   - Se debe asegurar que las referencias a `DatabaseError` sean consistentes
