<template>
  <div>
    <el-table :data="clients" :default-sort="{prop: 'user', order: 'ascending'}" style="width: 100%">
      <el-table-column type="expand">
        <template slot-scope="props">
          <div v-if="props.row.proxies && props.row.proxies.length > 0" style="padding: 10px 50px;">
            <h4 style="margin-bottom: 10px; color: #606266;">Port Mappings</h4>
            <el-table :data="props.row.proxies" size="small" border style="width: 100%">
              <el-table-column label="Name" prop="name" width="150"></el-table-column>
              <el-table-column label="Type" prop="type" width="80">
                <template slot-scope="scope">
                  <el-tag size="small">{{ scope.row.type }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="Server Port" width="120">
                <template slot-scope="scope">
                  <span v-if="scope.row.remote_port">:{{ scope.row.remote_port }}</span>
                  <span v-else>-</span>
                </template>
              </el-table-column>
              <el-table-column label="" width="40">
                <template>
                  <span style="color: #409EFF; font-weight: bold;">&rarr;</span>
                </template>
              </el-table-column>
              <el-table-column label="Local Address" width="200">
                <template slot-scope="scope">
                  <span>{{ scope.row.local_ip }}:{{ scope.row.local_port }}</span>
                </template>
              </el-table-column>
              <el-table-column label="Status" width="100">
                <template slot-scope="scope">
                  <el-tag type="success" size="small" v-if="scope.row.status === 'online'">{{ scope.row.status }}</el-tag>
                  <el-tag type="danger" size="small" v-else>{{ scope.row.status }}</el-tag>
                </template>
              </el-table-column>
            </el-table>
          </div>
          <div v-else style="padding: 10px 50px; color: #909399;">
            No proxies registered
          </div>
        </template>
      </el-table-column>
      <el-table-column label="User" prop="user" sortable width="120"></el-table-column>
      <el-table-column label="Run ID" prop="run_id" sortable width="200">
        <template slot-scope="scope">
          <span style="font-family: monospace; font-size: 12px;">{{ scope.row.run_id }}</span>
        </template>
      </el-table-column>
      <el-table-column label="Version" prop="version" sortable width="100"></el-table-column>
      <el-table-column label="Hostname" prop="hostname" sortable width="150"></el-table-column>
      <el-table-column label="OS / Arch" width="150">
        <template slot-scope="scope">
          <span>{{ scope.row.os }}/{{ scope.row.arch }}</span>
        </template>
      </el-table-column>
      <el-table-column label="Proxies" width="80">
        <template slot-scope="scope">
          <el-tag size="small" type="info">{{ scope.row.proxies ? scope.row.proxies.length : 0 }}</el-tag>
        </template>
      </el-table-column>
    </el-table>

    <div v-if="clients.length === 0" style="text-align: center; padding: 40px; color: #909399;">
      No connected clients
    </div>
  </div>
</template>

<script>
  export default {
    data() {
      return {
        clients: [],
        timer: null,
      }
    },
    created() {
      this.fetchData()
      this.timer = setInterval(this.fetchData, 5000)
    },
    beforeDestroy() {
      if (this.timer) {
        clearInterval(this.timer)
      }
    },
    watch: {
      '$route': 'fetchData'
    },
    methods: {
      fetchData() {
        fetch('../api/clients', {credentials: 'include'})
          .then(res => {
            return res.json()
          }).then(json => {
            this.clients = json.clients || []
          }).catch(() => {
            // ignore fetch errors
          })
      }
    }
  }
</script>

<style>
</style>
