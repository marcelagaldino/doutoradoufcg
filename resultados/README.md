# Conjunto de Dados

Este diretório contém os dados experimentais e a análise estatística relacionados à tese:  
*Fortalecendo a Confiança em Módulos de Plataforma Confiável Virtual através de Ancoragem Baseada em Integridade para Ambientes Hiperconvergentes.*

# Visão Geral dos Diretórios

- **memoria**: Inclui o conjunto de dados de utilização de memória com análise estatística
  - *memoria_dados.ziṕ*: contém os dados brutos de utilização de memória coletados durante as execuções experimentais.
  - *memoria_analise.csv*: fornece estatísticas resumidas de utilização de memória para cada cenário experimental e execução. 
  - *memoria_intervalo_de_confianca.csv*: contém os intervalos de confiança de 95% para utilização de memória, estimados utilizando uma abordagem de reamostragem bootstrap com 5.000 réplicas (n = 5000).
- **cpu**: Inclui o conjunto de dados de utilização de CPU com análise estatística
  - *cpu_dados.zip*: contém os dados brutos de utilização de CPU coletados durante as execuções experimentais.
  - *cpu_analise.csv*: fornece estatísticas resumidas de utilização de CPU para cada cenário experimental e execução. 
  - *cpu_intervalo_de_confianca.csv*: contém os intervalos de confiança de 95% para utilização de CPU, estimados utilizando uma abordagem de reamostragem bootstrap com 5.000 réplicas (n = 5000).
- **tempo_de_ancoragem/rede_local e tempo_de_ancoragem/rede_remota**: Inclui o conjunto de dados de tempo de ancoragem com análise estatística para o cenário em que os hosts estão na mesma rede e em redes geograficamente distribuídas, respectivamente. 
  - *tempo_data.zip*: contém os dados brutos de tempo de ancoragem coletados durante as execuções experimentais.
  - *tempo_analise.csv*: fornece estatísticas resumidas de tempo de ancoragem para cada cenário experimental e execução.
  - *tempo_intervalo_de_confianca.csv*: contém os intervalos de confiança de 95% para tempo de ancoragem, estimados utilizando uma abordagem de reamostragem bootstrap com 5.000 réplicas (n = 5000).
 
# Descrição dos Dados

---

| Field                     | Descrição                                                                  | Tipo            |
|---------------------------|----------------------------------------------------------------------------|-----------------|
| `timestamp`               | Momento em que a medição foi coletada (formato: HH:MM:SS)                  | `string`        |
| `memory_utilization`      | Utilização de memória em porcentagem                                       | `float`         |
| `cpu_utilization`         | Utilização de CPU em porcentagem                                           | `float`         |
| `kernel_memory_utilization`| Utilização de CPU em porcentagem                                           | `float`         |
| `number_extend`           | Número de operações extend realizadas durante o período de medição         | `integer`       |
| `host_id`                 | Identificador da máquina host onde a medição foi coletada                  | `string`        |
| `scenario`                | Identificador do cenário experimental                                      | `string`        |
| `execution_id`            | Identificador da execução do experimento                                   | `integer`       |
| `mean`                    | Média do conjunto de medições para a métrica alvo                          | `float`         |
| `ci_lower`                | Limite inferior do intervalo de confiança de 95% para a métrica alvo       | `float`         |
| `ci_upper`                | Limite superior do intervalo de confiança de 95% para a métrica alvo       | `float`         |
| `std`                     | Desvio padrão das medições para a métrica alvo                             | `float`         |
| `min`                     | Valor mínimo observado                                                     | `float`         |
| `percentile25`            | Percentil 25 dos valores observados                                        | `float`         |
| `percentile50`            | Percentil 50 (mediana) dos valores observados                              | `float`         |
| `percentile75`            | Percentil 75 dos valores observados                                        | `float`         |
| `max`                     | Valor máximo observado                                                     | `float`         |

---
