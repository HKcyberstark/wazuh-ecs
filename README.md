# wazuh-ecs

This project described the parsing of wazuh[HIDS] alert logs for elasticsearch with Elastic common schema using filebeat.

Goal of the project is to parse wazuh alerts logs directly from wazuh manager as simple as possible with Elastic common schema.

<img width="523" alt="Screenshot 2020-04-27 at 11 41 36 AM" src="https://user-images.githubusercontent.com/40884455/80339388-27023600-887c-11ea-9f50-7f0639f1832d.png">

**Warning** : The parsing and conversion of alerts data with Elastic common schema is experimental. As much as possible ECS fields are parsed and added as initial release. 

## Assumption
The project assumes that wazuh manager and elasticsearch are already installed. [Wazuh](https://documentation.wazuh.com/3.7/installation-guide/index.html) official Installation guide and [Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/install-elasticsearch.html) official guide to be used for more details. 

## Data parsing
Wazuh alerts data which in JSON format are to be read and decoded using structured and logging and multiline options with filebeat. These configuration options collect encoded JSON objects as a string spanning multiple lines.

```
multiline.pattern: '^{'
multiline.negate: true
multiline.match: after
```
Filebeat processors are used in decoding the JSON message into structured JSON objects and uniform naming convention with prefix as “wazuh” will be used across all the data parsed with wazuh alerts. 

```
Processor:
    - decode_json_fields:
        fields: ['message']
        target: "wazuh"
    - drop_fields:
        fields: ['message']
```
FIlebeat is configured with a configuration file that decodes multiline json alerts from wazuh and uses processors to decode into common naming convention

## ECS parsing
straightforward mapping of the original fields in the wazuh alert data to ECS related fields are  created with [ecs-mapper](https://github.com/elastic/ecs-mapper). ecs-mapper  is a tool to generate starter pipelines to help you get started quickly in mapping your event sources to ECS.

wazuh-ECS-mapping template sheet is maintained for mapping of alert data into ECS and used with ecs-mapper tool in generating pipelines. 

ECS mapper turns a field mapping CSV to roughly equivalent pipelines for:
Beats
Elasticsearch
Logstash
We would be using Elasticsearch ingest processor pipelines in the filebeat configuration for simple and less resource intensive field parsing. 

Additional fields added with ECS parsing on wazuh alerts are as below

| ECS field      | Field value         |
|----------------|---------------------|
| event.module   | wazuh               |
| event.kind     | alert               |
| event.category | intrusion_detection |


## Installation and Configuration
1. Install filebeat

Filebeat to be installed in the wazuh management server.  Repositories for YUM and APT is available with [official documentation](https://www.elastic.co/guide/en/beats/filebeat/current/setup-repositories.html)

2. Define the Pipeline

Define the pipeline in Elasticsearch that converts and adds ECS data to wazuh alerts.

```
# curl -so /etc/filebeat/wazuh-ecs-pipeline.json https://raw.githubusercontent.com/HKcyberstark/wazuh-ecs/master/wazuh-ecs-pipeline.json
# chmod go+r /etc/filebeat/wazuh-ecs-pipeline.json
```

```
# cd /etc/filebeat
```
<<YOUR_ELASTIC_SERVER_IP>> is the IP address of your elasticsearch to be used in the below command.
```
# curl -H 'Content-Type: application/json' -XPUT 'https://<<YOUR_ELASTIC_SERVER_IP>>/_ingest/pipeline/wazuh-ecs-pipeline-pipeline' -d@wazuh-ecs-pipeline.json
```

3. Filebeat configuration

```
# curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/HKcyberstark/wazuh-ecs/master/filebeat.yml
# chmod go+r /etc/filebeat/filebeat.yml
```
Edit the file /etc/filebeat/filebeat.yml and replace YOUR_ELASTIC_SERVER_IP with the IP address or the hostname of the Elasticsearch server. For example:

```
Output.elasticsearch
    host: [“https://YOUR_ELASTIC_SERVER_IP:9200”]
```

4. Run filebeat

For Systemd:
```
systemctl daemon-reload
systemctl enable filebeat.service
systemctl start filebeat.service
```
For SysV Init:
```
chkconfig --add filebeat
service filebeat start
```

## Field descriptions

| Field format | Description                                                    |
|--------------|----------------------------------------------------------------|
| host.*       | Details of server running the filebeat [usually wazuh manager] |
| agent.*      | Wazuh agent details                                            |
| event.*      | events related to wazuh alerts mapped with ECS                 |
| rule.*       | wazuh rule details mapped to ECS                               |
| wazuh.*      | original data fields from wazuh alert                          |

## Next steps
- [x] Initial ECS parsing for wazuh alerts
- [x] wazuh alerts to be populated in Elastic SIEM
- [ ] Pre built ECS dashboards for wazuh
- [ ] Elastic SIEM rules for wazuh alerts
- [ ] MITRE ATT&CK mapping for wazuh alerts

## Contribution
Continuous enhancement and improvement with ECS parsing with latest version of elasticstack is the development goal of the project. Help with your expertise to enhance the project.
