# 🤖 AI-Orchestration Development Workflow

Este proyecto representa una implementación de **Seguridad Financiera** desarrollada bajo un modelo de **Orquestación de Agentes de IA**. En lugar de un desarrollo lineal, se utilizó una triangulación de capacidades entre el criterio humano y dos modelos de lenguaje avanzado (LLMs) con roles diferenciados.

## 🏗️ Metodología: Human-in-the-Loop + Multi-Agent Workflow

Para garantizar el cumplimiento de normativas **PCI PIN** y **ANSI X9.143**, se diseñó un flujo de trabajo basado en el concepto de **Chain of Thought (CoT)**, optimizando la precisión técnica y la eficiencia de recursos (tokens).

### 1. El Supervisor Humano (Lead Architect)
**Rol:** Definición de objetivos, validación de seguridad y supervisión de la lógica de negocio.
* **Aporte:** Identificación de los 3 hitos críticos (KEK, PEK, BDK) y supervisión de la jerarquía de llaves para evitar el compromiso de datos en memoria.

### 2. El Security Architect (Gemini Custom Agent - "The Gem")
**Rol:** Meta-Prompter y Validador de Estándares.
* **Proceso:** Se configuró un **Gem especializado** cargado con el contexto de normativas bancarias. Su función fue actuar como un "Traductor de Requerimientos a Prompts Operativos".
* **Eficiencia de Tokens:** Este agente refinó las instrucciones antes de enviarlas al modelo de ejecución, eliminando ruido y asegurando que las reglas de **Zero-Encryption (ECB)** para TDES y **CMAC** para AES fueran explícitas, minimizando iteraciones innecesarias y optimizando el consumo de tokens.

### 3. El Technical Coder (Claude 3.5 Sonnet)
**Rol:** Ejecución de Código y Manejo de Excepciones.
* **Proceso:** Recibió los prompts optimizados por el Arquitecto (Gemini) para generar una estructura de archivos modular y limpia.
* **Resultado:** Implementación de un CLI robusto con **Cero Hardcoding**, permitiendo que la herramienta sea genérica y acepte tanto cadenas hexadecimales como rutas de archivos.

---

## 🧠 Evolución y Pivot Técnico: El Problema del KCV

Uno de los puntos más destacados de este workflow fue la resolución de la validación del **Check Value (KCV)** para la BDK.

1.  **Detección:** El flujo identificó un error de validación cuando se intentaba tratar a la BDK (Triple DES) con el mismo algoritmo de la KEK (AES).
2.  **Razonamiento (CoT):** A través del Agente Arquitecto, se determinó que el estándar exige algoritmos distintos según la longitud de la llave.
3.  **Implementación:** Se instruyó al Coder para crear una **Lógica de KCV Inteligente**:
    * **Llaves de 16/24 bytes (TDES):** Validación mediante cifrado de bloque de ceros en modo ECB.
    * **Llaves de 32 bytes (AES):** Validación mediante AES-CMAC.

---

## 🛠️ Prompts Maestros Utilizados (Log de Ingeniería)

Para transparencia del proceso, se incluyen fragmentos de la cadena de instrucciones:

* **Prompt de Inicialización:** *"Actuá como mi Senior Lead Developer. Vamos a iniciar el proyecto key_exchange desde cero con una estructura profesional y limpia. Misión: Crear el esqueleto del paquete..."*
* **Prompt de Lógica Criptográfica:** *"Necesito implementar el módulo de recombinación y validación de una KEK... Genera una función XOR byte a byte... y una validación de KCV (AES-CMAC) con bloque de 16 bytes en cero..."*
* **Prompt de Refactorización de Librería:** *"Claudio, durante las pruebas saltó un AttributeError en psec... Refactorizá para usar tr31_module.wrap y asegurar que no haya prefijos erróneos en los headers..."*

---

## 📊 Conceptos de Eficiencia Aplicados

| Concepto | Aplicación en el Proyecto |
| :--- | :--- |
| **Token Optimization** | Uso de Gemini para destilar instrucciones complejas en prompts quirúrgicos para Claude. |
| **Agentic Roleplay** | Asignación de roles especializados para evitar alucinaciones en estándares ANSI. |
| **Integrity Checks** | Implementación de `IntegrityError` y `SecurityError` para desacoplar fallos de formato de fallos de MAC. |

---
*Este flujo demuestra cómo la orquestación inteligente de IA permite desarrollar herramientas de grado industrial en tiempos récord, manteniendo una precisión técnica total en dominios críticos como la seguridad financiera.*