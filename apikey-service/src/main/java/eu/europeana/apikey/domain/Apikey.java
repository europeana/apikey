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
	private String apikey;

	@NotNull
	@Size(min = 1, max = 30)
	@Column(name = "privatekey")
	@JsonProperty("privatekey")
	private String privatekey;

	@NotNull
	@Column(name = "registrationdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("registrationDate")
	@JsonView(View.Public.class)
	private Date registrationDate;

	@Column(name = "usagelimit")
	@JsonProperty("usageLimit")
	@JsonView(View.Public.class)
	private Long usageLimit;

	@Size(max = 100)
	@Column(name = "website")
	@JsonProperty("website")
	@JsonView(View.Public.class)
	private String website;

	@Column(name = "activationdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("activationDate")
	@JsonView(View.Public.class)
	private Date activationDate;

	@Size(max = 255)
	@Column(name = "appname")
	@JsonProperty("appName")
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
	@JsonProperty("firstName")
	@JsonView(View.Public.class)
	protected String firstName;

	@NotNull
	@Size(max = 50)
	@Column(name = "lastname")
	@JsonProperty("lastName")
	@JsonView(View.Public.class)
	protected String lastName;

	@NotNull
	@Size(max = 8)
	@Column(name = "level")
	@JsonProperty("level")
	private String level;

	@Column(name = "deprecationdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("deprecationDate")
	@JsonView(View.Public.class)
	private Date deprecationDate;

	@Column(name = "lastaccessdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("lastAccessDate")
	@JsonView(View.Public.class)
	private Date lastAccessDate;

	@NotNull
	@Column(name = "usage")
	@JsonProperty("usage")
	@JsonView(View.Public.class)
	private Long usage;

	public Apikey() {

	}

	public Apikey(String apikey, String privatekey, String firstName, String lastName, String email, String level) {
		this.apikey = apikey;
		this.privatekey = privatekey;
		this.firstName = firstName;
		this.lastName = lastName;
		this.email = email;
		this.level = level;
		this.registrationDate = new Date();
		this.usageLimit = 10000L;
		this.usage = 0L;
	}

	public String getApikey() {
		return apikey;
	}

	public void setApikey(String apikey) {
		this.apikey = apikey;
	}

	public String getPrivatekey() {
		return privatekey;
	}

	public void setPrivatekey(String privatekey) {
		this.privatekey = privatekey;
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

	public Date getLastAccessDate() {
		return lastAccessDate;
	}

	public void setLastAccessDate(Date lastAccessDate) {
		this.lastAccessDate = lastAccessDate;
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
				" apikey = " + apikey +
				", privatekey = " + nvl(privatekey) +
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
				", lastAccessDate = " + nvl(lastAccessDate) +
				", deprecationDate = " + nvl(deprecationDate) +
				" }";
	}

}
