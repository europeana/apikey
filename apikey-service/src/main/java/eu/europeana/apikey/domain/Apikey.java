/*
 * Copyright 2007-2017 The Europeana Foundation
 *
 *  Licenced under the EUPL, Version 1.1 (the "Licence") and subsequent versions as approved
 *  by the European Commission;
 *  You may not use this work except in compliance with the Licence.
 *
 *  You may obtain a copy of the Licence at:
 *  http://joinup.ec.europa.eu/software/page/eupl
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under
 *  the Licence is distributed on an "AS IS" basis, without warranties or conditions of
 *  any kind, either express or implied.
 *  See the Licence for the specific language governing permissions and limitations under
 *  the Licence.
 */

/**
 * Created by luthien on 18/04/2017.
 */

package eu.europeana.apikey.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.format.annotation.DateTimeFormat;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Date;

import static eu.europeana.apikey.util.Tools.nvl;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Entity
@Table(name = "apikey")
public class Apikey {
	@Id
//	@GeneratedValue(strategy = GenerationType.AUTO)
	@Column(name = "apikey")
	@JsonProperty("apikey")
	@JsonView(View.Public.class)
	private String apiKey;

	@NotNull
	@Size(min = 1, max = 30)
	@Column(name = "privatekey")
	@JsonProperty("privatekey")
	private String privateKey;

	@NotNull
	@Column(name = "registrationdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("registrationdate")
	@JsonView(View.Public.class)
	private Date registrationDate;

	@Column(name = "usagelimit")
	@JsonProperty("usagelimit")
	@JsonView(View.Public.class)
	private Long usageLimit;

	@Size(max = 100)
	@Column(name = "website")
	@JsonProperty("website")
	@JsonView(View.Public.class)
	private String website;

	@Column(name = "activationdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("activationdate")
	@JsonView(View.Public.class)
	private Date activationDate;

	@Size(max = 255)
	@Column(name = "appname")
	@JsonProperty("appname")
	@JsonView(View.Public.class)
	protected String appName;

	@Size(max = 100)
	@Column(name = "company")
	@JsonProperty("company")
	@JsonView(View.Public.class)
	protected String company;

	@Size(max = 255)
	@Column(name = "sector")
	@JsonProperty("sector")
	@JsonView(View.Public.class)
	protected String sector;

	@NotNull
	@Size(max = 100)
	@Column(name = "email")
	@JsonProperty("email")
	@JsonView(View.Public.class)
	protected String email;

	@NotNull
	@Size(max = 50)
	@Column(name = "firstname")
	@JsonProperty("firstname")
	@JsonView(View.Public.class)
	protected String firstName;

	@NotNull
	@Size(max = 50)
	@Column(name = "lastname")
	@JsonProperty("lastname")
	@JsonView(View.Public.class)
	protected String lastName;

	@NotNull
	@Size(max = 8)
	@Column(name = "level")
	@JsonProperty("level")
	private String level;

	@Column(name = "deprecationdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("deprecationdate")
	@JsonView(View.Public.class)
	private Date deprecationDate;

	@Column(name = "lastaccessdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("lastaccessdate")
	@JsonView(View.Public.class)
	private Date lastaccessDate;

	@NotNull
	@Column(name = "usage")
	@JsonProperty("usage")
	@JsonView(View.Public.class)
	private Long usage;

	public Apikey() {

	}

	public Apikey(String apiKey, String privateKey, String firstName, String lastName, String email, String level) {
		this.apiKey = apiKey;
		this.privateKey = privateKey;
		this.firstName = firstName;
		this.lastName = lastName;
		this.email = email;
		this.level = level;
		this.registrationDate = new Date();
		this.usageLimit = 10000L;
		this.usage = 0L;
	}

	public String getApiKey() {
		return apiKey;
	}

	public void setApiKey(String apiKey) {
		this.apiKey = apiKey;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	public Date getRegistrationDate() {
		return registrationDate;
	}

	public void setRegistrationDate(Date registrationDate) {
		this.registrationDate = registrationDate;
	}

	public Long getUsageLimit() {
		return usageLimit;
	}

	public void setUsageLimit(Long usageLimit) {
		this.usageLimit = usageLimit;
	}

	public String getWebsite() {
		return website;
	}

	public void setWebsite(String website) {
		this.website = website;
	}

	public Date getActivationDate() {
		return activationDate;
	}

	public void setActivationDate(Date activationDate) {
		this.activationDate = activationDate;
	}

	public String getAppName() {
		return appName;
	}

	public void setAppName(String appName) {
		this.appName = appName;
	}

	public String getCompany() {
		return company;
	}

	public void setCompany(String company) {
		this.company = company;
	}

	public String getSector() {
		return sector;
	}

	public void setSector(String sector) {
		this.sector = sector;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getLevel() {
		return level;
	}

	public void setLevel(String level) {
		this.level = level;
	}

	public Date getDeprecationDate() {
		return deprecationDate;
	}

	public void setDeprecationDate(Date deprecationDate) {
		this.deprecationDate = deprecationDate;
	}

	public Date getLastaccessDate() {
		return lastaccessDate;
	}

	public void setLastaccessDate(Date lastaccessDate) {
		this.lastaccessDate = lastaccessDate;
	}

	public Long getUsage() {
		return usage;
	}

	public void setUsage(Long usage) {
		this.usage = usage;
	}


	@Override
	public String toString() {
		return "Apikey {" +
				" apiKey = " + apiKey +
				", privateKey = " + nvl(privateKey) +
				", firstName = " + nvl(firstName) +
				", lastName = " + nvl(lastName) +
				", email = " + nvl(email) +
				", level = " + nvl(level) +
				", usage = " + nvl(usage) +
				", usageLimit = " + nvl(usageLimit) +
				", appName = " + nvl(appName) +
				", website = " + nvl(website) +
				", company = " + nvl(company) +
				", sector = " + nvl(sector) +
				", activationDate = " + nvl(activationDate) +
				", registrationDate = " + nvl(registrationDate) +
				", lastaccessDate = " + nvl(lastaccessDate) +
				", deprecationDate = " + nvl(deprecationDate) +
				" }";
	}

}
