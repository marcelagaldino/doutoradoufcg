# Sobre este repositório


Este repositório contém todos os códigos e arquivos de configuração necessários para executar a solução proposta na tese de doutorado intitulada "**Fortalecendo a Confiança em Módulos de Plataforma Confiável Virtual através de Ancoragem Baseada em Integridade para Ambientes Hiperconvergentes**". O objetivo é permitir a reprodutibilidade da pesquisa, possibilitando que outros pesquisadores e profissionais repliquem os experimentos, validem os resultados e utilizem o código como base para trabalhos futuros.

Cada diretório do repositório corresponde a um bloco funcional da solução e contém um arquivo README.md com instruções específicas para execução.

O conteúdo inclui:

- **MavTPMg**: Módulo de Kernel em execução nos Hosts com TPM, responsável por realizar a ancoragem do vTPMg no chip TPM.
- **MavTPMu**: Módulo de Kernel em execução na VMg, responsável por realizar a ancoragem dos vTPMus no vTPMg. Além de realizar a ancoragem dos vTPMgs remotos, localizados em máquinas que não dispõem de chip TPM localmente ou que necessitam de replicação de informação.
- **SG_API**: API para comunicação entre VMs de gerenciamento. A API recebe solicitações, autentica e valida as informações de estado recebidas.
- **Agent-Host**: Componente responsável por receber as medições provenientes do emulador de software, identificar se pertencem ao vTPMg ou ao vTPMu e encaminhá-las ao elemento adequado para realizar a ancoragem. No Host com TPM, o Agent-Host envia os dados de ancoragem ao MAvTPMu quando a medição refere-se ao vTPMu e ao MAvTPMg quando refere-se ao vTPMg. No Host sem TPM, o Agent-Host encaminha os dados de ancoragem de ambos, vTPMu e vTPMg, para o MAvTPMu.
- **swtpm_libtpms**: Implementação do emulador de software TPM (swtpm) e de sua biblioteca principal (libtpms), modificadas para dar suporte à solução proposta, com a finalidade de reportar as alterações de estado.
